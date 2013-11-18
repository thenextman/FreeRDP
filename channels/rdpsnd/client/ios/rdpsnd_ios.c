/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Output Virtual Channel
 *
 * Copyright 2013 Dell Software <Mike.McDonald@software.dell.com>
 * Copyright 2013 Corey Clayton <can.of.tuna@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/crt.h>
#include <winpr/wtypes.h>
#include <winpr/synch.h>
#include <winpr/sysinfo.h>
#include <winpr/collections.h>

#include <freerdp/types.h>
#include <freerdp/codec/dsp.h>
#include <freerdp/utils/svc_plugin.h>

#import <AudioToolbox/AudioToolbox.h>
#import <AudioToolbox/AudioQueue.h>

#include "rdpsnd_main.h"

#define IOS_USE_AUDIO_QUEUE		1

#define AUDIO_QUEUE_NUM_BUFFERS		16
#define AUDIO_QUEUE_BUFFER_SIZE		(32 * 1024)

struct rdpsnd_ios_plugin
{
	rdpsndDevicePlugin device;
	
	BOOL isOpen;
	BOOL isPlaying;
	BOOL isRunning;
	int bytesPerFrame;
	
	wBufferPool* pool;
	AUDIO_FORMAT format;
	
	wQueue* RenderQueue;
	wQueue* PendingQueue;
	
	UINT16 wPlaybackDelay;
	UINT32 inNumberBytes;
	UINT32 wBufferedTime;
	
	CRITICAL_SECTION lock;
	AudioComponentInstance audioUnit;
	AudioStreamBasicDescription audioFormat;
	
	int audioQueueSize;
	AudioQueueRef audioQueue;
	AudioQueueTimelineRef audioTimeline;
};
typedef struct rdpsnd_ios_plugin rdpsndIOSPlugin;

#ifndef IOS_USE_AUDIO_QUEUE

static OSStatus rdpsnd_ios_render_notify_cb(
				      void* inRefCon,
				      AudioUnitRenderActionFlags* ioActionFlags,
				      const AudioTimeStamp* inTimeStamp,
				      UInt32 inBusNumber,
				      UInt32 inNumberFrames,
				      AudioBufferList* ioData
				      )
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inRefCon;
	
	if (*ioActionFlags == kAudioUnitRenderAction_PostRender)
	{
		int inNumberBytes;
		RDPSND_WAVE* wave;
		AudioBuffer* audioBuffer = &ioData->mBuffers[0];
		
		inNumberBytes = inNumberFrames * ios->bytesPerFrame;
		inNumberBytes /= (ios->format.nChannels / audioBuffer->mNumberChannels);
		ios->inNumberBytes += inNumberBytes;
		
#if 1
		printf("AudioUnitRenderNotifyCallback: inNumberFrames: %d inNumberBytes: %d mDataByteSize: %d\n",
		       (unsigned int) inNumberFrames, inNumberBytes,
		       (unsigned int) audioBuffer->mDataByteSize);
#endif
		
		wave = Queue_Peek(ios->RenderQueue);
		
		if (!wave)
			return noErr;
		
		if (ios->inNumberBytes >= wave->length)
		{
			UINT32 wTimeDiff;
			UINT32 wCurrentTime;
			
			wave = Queue_Dequeue(ios->RenderQueue);
			
			wCurrentTime = GetTickCount();
			wave->wLocalTimeB = wCurrentTime;
			wTimeDiff = wave->wLocalTimeB - wave->wLocalTimeA;
			wave->wTimeStampB = wave->wTimeStampA + wTimeDiff;
			
			ios->device.WaveConfirm(&ios->device, wave);
			
			printf("\tWaveConfirm wBlockNo: %d wTimeStampA: %d wTimeStampB: %d wTimeDiff: %d wAudioLength: %d\n",
			       wave->cBlockNo, wave->wTimeStampA, wave->wTimeStampB, wTimeDiff, wave->wAudioLength);
			
			BufferPool_Return(ios->pool, wave->data);
			ios->inNumberBytes = 0;
		}
	}
	
	return noErr;
}

/* This callback is used to feed the audio unit buffers */
static OSStatus rdpsnd_ios_render_cb(
				     void* inRefCon,
				     AudioUnitRenderActionFlags* ioActionFlags,
				     const AudioTimeStamp* inTimeStamp,
				     UInt32 inBusNumber,
				     UInt32 inNumberFrames,
				     AudioBufferList* ioData
				     )
{
	unsigned int i;
	RDPSND_WAVE* wave;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inRefCon;
	
	if (inBusNumber != 0)
		return noErr;
	
	wave = Queue_Peek(ios->PendingQueue);
	
	for (i = 0; i < ioData->mNumberBuffers; i++)
	{
		AudioBuffer* audioBuffer = &ioData->mBuffers[i];
		
		if (wave)
		{
			int waveLength = (wave->length - wave->offset);
			int mDataByteSize = audioBuffer->mDataByteSize;
			int copyLength = (waveLength > mDataByteSize) ? mDataByteSize : waveLength;
			
#if 1
			printf("AudioUnitRenderCallback: inNumberFrames: %d inNumberBytes: %d mDataByteSize: %d wAudioLength: %d\n",
			       (unsigned int) inNumberFrames, copyLength,
			       (unsigned int) audioBuffer->mDataByteSize, wave->wAudioLength);
#endif
			
			CopyMemory(audioBuffer->mData, &(wave->data[wave->offset]), copyLength);
			audioBuffer->mDataByteSize = copyLength;
			wave->offset += copyLength;
			
			if (wave->offset >= wave->length)
			{
				wave = Queue_Dequeue(ios->PendingQueue);
				Queue_Enqueue(ios->RenderQueue, wave);
			}
		}
		else
		{
			*ioActionFlags |= kAudioUnitRenderAction_OutputIsSilence;
			
			audioBuffer->mDataByteSize = 0;
			AudioOutputUnitStop(ios->audioUnit);
			ios->isPlaying = FALSE;
			
			printf("Buffer underrun!\n");
		}
	}
	
	return noErr;
}

#else

static void ios_audio_queue_output_cb(void* inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inUserData;
	
	AudioQueueFreeBuffer(inAQ, inBuffer);
	ios->audioQueueSize--;
}

static void ios_audio_queue_property_listener_cb(void* inUserData, AudioQueueRef inAQ, AudioQueuePropertyID inID)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inUserData;
	
	if (inID == kAudioQueueProperty_IsRunning)
	{
		OSStatus status;
		UInt32 propertySize;
		
		UInt32 isRunning;
		propertySize = sizeof(isRunning);
		
		status = AudioQueueGetProperty(ios->audioQueue,
				      kAudioQueueProperty_IsRunning,
				      &isRunning,
				      &propertySize);
		
		if (status != 0)
		{
			printf("AudioQueueGetProperty failure: kAudioQueueProperty_IsRunning\n");
		}
		
		printf("kAudioQueueProperty_IsRunning: %d\n", (int) isRunning);
		
		ios->isRunning = (BOOL) isRunning;
		ios->wBufferedTime = 0;
	}
}

#endif

static BOOL rdpsnd_ios_format_supported(rdpsndDevicePlugin* __unused device, AUDIO_FORMAT* format)
{
	if (format->wFormatTag == WAVE_FORMAT_PCM)
	{
		return TRUE;
	}
	else if (format->wFormatTag == WAVE_FORMAT_ALAW)
	{
		return TRUE;
	}
	else if (format->wFormatTag == WAVE_FORMAT_MULAW)
	{
		return TRUE;
	}
	
	return FALSE;
}

static void rdpsnd_ios_set_format(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int __unused latency)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	CopyMemory(&(ios->format), format, sizeof(AUDIO_FORMAT));
	
	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_ALAW:
			ios->audioFormat.mFormatID = kAudioFormatALaw;
			break;
			
		case WAVE_FORMAT_MULAW:
			ios->audioFormat.mFormatID = kAudioFormatULaw;
			break;
			
		case WAVE_FORMAT_PCM:
			ios->audioFormat.mFormatID = kAudioFormatLinearPCM;
			break;
			
		default:
			break;
	}
	
	ios->audioFormat.mSampleRate = format->nSamplesPerSec;
	ios->audioFormat.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
	ios->audioFormat.mFramesPerPacket = 1;
	ios->audioFormat.mChannelsPerFrame = format->nChannels;
	ios->audioFormat.mBitsPerChannel = format->wBitsPerSample;
	ios->audioFormat.mBytesPerFrame = (format->wBitsPerSample * format->nChannels) / 8;
	ios->audioFormat.mBytesPerPacket = format->nBlockAlign;
	
	ios->bytesPerFrame = ios->audioFormat.mBytesPerFrame;
	
	rdpsnd_print_audio_format(format);
}

static void rdpsnd_ios_set_volume(rdpsndDevicePlugin* __unused device, UINT32 __unused value)
{
	
}

static void rdpsnd_ios_start(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;

	if (!ios->isPlaying)
	{
		OSStatus status;
		
#ifdef IOS_USE_AUDIO_QUEUE
		if (!ios->audioQueue)
			return;
		
		status = AudioQueueStart(ios->audioQueue, NULL);
		
		if (status == 0)
			ios->isPlaying = TRUE;
#else
		if (!ios->audioUnit)
			return;
		
		status = AudioOutputUnitStart(ios->audioUnit);
		
		if (status == 0)
			ios->isPlaying = TRUE;
#endif
	}
}

static void rdpsnd_ios_stop(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;

	if (ios->isPlaying)
	{
#ifndef IOS_USE_AUDIO_QUEUE
		AudioOutputUnitStop(ios->audioUnit);
#endif
		AudioSessionSetActive(false);
		ios->isPlaying = FALSE;
	}
}

static void rdpsnd_ios_wave_play(rdpsndDevicePlugin* device, RDPSND_WAVE* wave)
{
	int length;
	BYTE* data;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	data = wave->data;
	length = wave->length;
	
#ifdef IOS_USE_AUDIO_QUEUE
	OSStatus status;
	AudioQueueBufferRef audioBuffer;
	
	status = AudioQueueAllocateBuffer(ios->audioQueue, wave->length, &audioBuffer);
	
	if (status != 0)
	{
		printf("AudioQueueAllocateBuffer failed\n");
	}
	
	CopyMemory(audioBuffer->mAudioData, (char*) data, wave->length);
	audioBuffer->mAudioDataByteSize = wave->length;
	
	AudioTimeStamp outActualStartTime;
	
	status = AudioQueueEnqueueBufferWithParameters(ios->audioQueue, audioBuffer, 0, NULL,
					      0, 0, 0, NULL, NULL, &outActualStartTime);
	
	if (status != 0)
	{
		printf("AudioQueueEnqueueBufferWithParameters failure\n");
	}
	
	ios->audioQueueSize++;
	wave->AutoConfirm = TRUE;
	
	UINT32 wTimeDiff;
	
	if (ios->isRunning)
	{
		AudioTimeStamp outTimeStamp;
		Boolean outTimelineDiscontinuity;
	
		status = AudioQueueGetCurrentTime(ios->audioQueue,
					  ios->audioTimeline,
					  &outTimeStamp,
					  &outTimelineDiscontinuity);
		
		if (status != 0)
		{
			printf("AudioQueueGetCurrentTime failure\n");
		}
		
		Float64 mSampleTimeDiff = outActualStartTime.mSampleTime - outTimeStamp.mSampleTime;
		wTimeDiff = ((UINT32) (mSampleTimeDiff / 1000.0)) + wave->wAudioLength;
	}
	else
	{
		ios->wBufferedTime += wave->wAudioLength;
		wTimeDiff = ios->wBufferedTime;
	}
	
	printf("AudioQueueTime: wTimeDiff: %d\n", wTimeDiff);
	
	wave->wTimeStampB = wave->wTimeStampA + wTimeDiff;
#else
	wave->offset = 0;
	wave->data = (BYTE*) BufferPool_Take(ios->pool, length);
	
	CopyMemory(wave->data, data, length);
	wave->AutoConfirm = FALSE;
	
	Queue_Enqueue(ios->PendingQueue, wave);
#endif
	
#if 1
	printf("Enqueue: wave [cBlockNo: %02X wLocalTimeA: %d wTimeStampA: %d frames: %d audioQueueSize: %d]\n",
	       wave->cBlockNo,
	       wave->wLocalTimeA,
	       wave->wTimeStampA,
	       (length / ios->bytesPerFrame), ios->audioQueueSize);
#endif
	
	rdpsnd_ios_start(device);
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int latency)
{
	OSStatus status;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	if (ios->isOpen)
		return;
	
	printf("rdpsnd_ios_open\n");
	
	device->SetFormat(device, format, 200);
	
#ifndef IOS_USE_AUDIO_QUEUE
	/* Find the output audio unit. */
	AudioComponentDescription desc;
	desc.componentManufacturer = kAudioUnitManufacturer_Apple;
	desc.componentType = kAudioUnitType_Output;
	desc.componentSubType = kAudioUnitSubType_RemoteIO;
	desc.componentFlags = 0;
	desc.componentFlagsMask = 0;
	
	AudioComponent audioComponent = AudioComponentFindNext(NULL, &desc);
	
	if (!audioComponent)
	{
		printf("AudioComponentFindNext failure\n");
		return;
	}
	
	/* Open the audio unit. */
	status = AudioComponentInstanceNew(audioComponent, &ios->audioUnit);
	
	if (status != 0)
	{
		printf("AudioComponentInstanceNew failure\n");
		return;
	}

	status = AudioUnitSetProperty(ios->audioUnit,
				      kAudioUnitProperty_StreamFormat,
				      kAudioUnitScope_Input,
				      0,
				      &(ios->audioFormat),
				      sizeof(ios->audioFormat));
	
	if (status != 0)
	{
		printf("Failed to set audio unit property\n");
		AudioComponentInstanceDispose(ios->audioUnit);
		ios->audioUnit = NULL;
		return;
	}
	
	/* Register Audio Unit Render Callback */
	
	AURenderCallbackStruct callbackStruct = { 0 };
	callbackStruct.inputProc = rdpsnd_ios_render_cb;
	callbackStruct.inputProcRefCon = ios;
	status = AudioUnitSetProperty(ios->audioUnit,
				      kAudioUnitProperty_SetRenderCallback,
				      kAudioUnitScope_Input,
				      0,
				      &callbackStruct,
				      sizeof(callbackStruct));
	
	if (status != 0)
	{
		printf("Failed to set audio unit callback\n");
		AudioComponentInstanceDispose(ios->audioUnit);
		ios->audioUnit = NULL;
		return;
	}
	
	/* Render Notify Callback */
	status = AudioUnitAddRenderNotify(ios->audioUnit, rdpsnd_ios_render_notify_cb, ios);
	
	if (status != 0)
	{
		printf("Could not register render notify callback!\n");
		AudioComponentInstanceDispose(ios->audioUnit);
		ios->audioUnit = NULL;
		return;
	}
	
	/* Initialize the AudioUnit. */
	status = AudioUnitInitialize(ios->audioUnit);
	
	if (status != 0)
	{
		printf("Failed to init the Audio Unit\n");
		AudioComponentInstanceDispose(ios->audioUnit);
		ios->audioUnit = NULL;
		return;
	}
#else
	status = AudioQueueNewOutput(&(ios->audioFormat),
				 ios_audio_queue_output_cb, ios,
				 NULL, NULL, 0, &(ios->audioQueue));
	
	if (status != 0)
	{
		printf("AudioQueueNewOutput failure\n");
		return;
	}
	
	status = AudioQueueCreateTimeline(ios->audioQueue, &(ios->audioTimeline));

	if (status != 0)
	{
		printf("AudioQueueCreateTimeline failure\n");
		return;
	}
	
	status = AudioQueueAddPropertyListener(ios->audioQueue, kAudioQueueProperty_IsRunning,
					       ios_audio_queue_property_listener_cb, ios);
	
	if (status != 0)
	{
		printf("AudioQueueAddPropertyListener failure\n");
	}
#endif
	
	status = AudioSessionInitialize(NULL, NULL, NULL, NULL);
	
	Float32 preferredBufferSize = 0.02; /* seconds */
	status = AudioSessionSetProperty(kAudioSessionProperty_PreferredHardwareIOBufferDuration, sizeof(preferredBufferSize), &preferredBufferSize);
	
	if (status != 0)
	{
		printf("AudioSessionSetProperty failed kAudioSessionProperty_PreferredHardwareIOBufferDuration\n");
	}
	
	UInt32 propertySize;
	
	Float64 hardwareSampleRate;
	Float32 hardwareBufferDuration;
	UInt32 hardwareOutputNumberChannels;
	
	propertySize = sizeof(hardwareSampleRate);
	status = AudioSessionGetProperty(kAudioSessionProperty_CurrentHardwareSampleRate, &propertySize, &hardwareSampleRate);
	
	if (status != 0)
	{
		printf("AudioSessionGetProperty failed kAudioSessionProperty_CurrentHardwareIOBufferDuration\n");
	}
	
	propertySize = sizeof(hardwareBufferDuration);
	status = AudioSessionGetProperty(kAudioSessionProperty_CurrentHardwareIOBufferDuration, &propertySize, &hardwareBufferDuration);
	
	if (status != 0)
	{
		printf("AudioSessionGetProperty failed kAudioSessionProperty_CurrentHardwareIOBufferDuration\n");
	}
	
	propertySize = sizeof(hardwareOutputNumberChannels);
	status = AudioSessionGetProperty(kAudioSessionProperty_CurrentHardwareOutputNumberChannels, &propertySize, &hardwareOutputNumberChannels);
	
	if (status != 0)
	{
		printf("AudioSessionGetProperty failed kAudioSessionProperty_CurrentHardwareOutputNumberChannels\n");
	}
	
	UInt32 bufferLengthInFrames = (ceil(hardwareSampleRate * hardwareBufferDuration) / hardwareOutputNumberChannels);
	
	printf("buffer length in frames: %d\n", (int) bufferLengthInFrames);
	printf("kAudioSessionProperty_CurrentHardwareSampleRate: %f\n", hardwareSampleRate);
	printf("kAudioSessionProperty_CurrentHardwareIOBufferDuration: %f\n", hardwareBufferDuration);
	printf("kAudioSessionProperty_CurrentHardwareOutputNumberChannels: %d\n", (int) hardwareOutputNumberChannels);
	
	status = AudioSessionSetActive(true);
	
	ios->isOpen = TRUE;
	
#ifdef IOS_USE_AUDIO_QUEUE
	
	UInt32 DecodeBufferSizeFrames;
	propertySize = sizeof(DecodeBufferSizeFrames);
	
	AudioQueueGetProperty(ios->audioQueue,
			      kAudioQueueProperty_DecodeBufferSizeFrames,
			      &DecodeBufferSizeFrames,
			      &propertySize);
	
	if (status != 0)
	{
		printf("AudioQueueGetProperty failure: kAudioQueueProperty_DecodeBufferSizeFrames\n");
	}
	
	printf("kAudioQueueProperty_DecodeBufferSizeFrames: %d\n", (int) DecodeBufferSizeFrames);
	
#else
	Float64 latency64 = 0;
	propertySize = sizeof(latency64);
	
	status = AudioUnitGetProperty(ios->audioUnit,
				      kAudioUnitProperty_Latency,
				      kAudioUnitScope_Global,
				      0,
				      &latency64,
				      &propertySize);
	
	if (status != 0)
	{
		printf("AudioUnitGetProperty: failed to query kAudioUnitProperty_Latency\n");
	}
	
	printf("audio unit latency: %.06fms\n", latency64 * 1000.0);
	
	ios->wPlaybackDelay = (UINT16) (latency64 * 1000.0);
#endif
}

static void rdpsnd_ios_close(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	printf("rdpsnd_ios_close\n");
	
	rdpsnd_ios_stop(device);
	
	if (ios->isOpen)
	{
#ifdef IOS_USE_AUDIO_QUEUE
		AudioQueueStop(ios->audioQueue, 0);
		AudioQueueDispose(ios->audioQueue, true);
		ios->audioQueue = NULL;
		ios->audioQueueSize = 0;
#else
		AudioUnitUninitialize(ios->audioUnit);
		AudioComponentInstanceDispose(ios->audioUnit);
		ios->audioUnit = NULL;
#endif
		ios->isOpen = FALSE;
	}
}

static void rdpsnd_ios_free(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	rdpsnd_ios_close(device);
	
	Queue_Free(ios->PendingQueue);
	Queue_Free(ios->RenderQueue);
	BufferPool_Free(ios->pool);

	free(ios);
}

#ifdef STATIC_CHANNELS
#define freerdp_rdpsnd_client_subsystem_entry	ios_freerdp_rdpsnd_client_subsystem_entry
#endif

int freerdp_rdpsnd_client_subsystem_entry(PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) malloc(sizeof(rdpsndIOSPlugin));
	
	if (ios)
	{
		ZeroMemory(ios, sizeof(rdpsndIOSPlugin));
	
		ios->device.Open = rdpsnd_ios_open;
		ios->device.FormatSupported = rdpsnd_ios_format_supported;
		ios->device.SetFormat = rdpsnd_ios_set_format;
		ios->device.SetVolume = rdpsnd_ios_set_volume;
		ios->device.Start = rdpsnd_ios_start;
		ios->device.Close = rdpsnd_ios_close;
		ios->device.Free = rdpsnd_ios_free;
		ios->device.WavePlay = rdpsnd_ios_wave_play;
	
		InitializeCriticalSectionAndSpinCount(&(ios->lock), 4000);
		
		ios->RenderQueue = Queue_New(TRUE, 0, 0);
		ios->PendingQueue = Queue_New(TRUE, 0, 0);
		ios->pool = BufferPool_New(TRUE, -1, 0);
		
		pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) ios);
	}
	
	return 0;
}
