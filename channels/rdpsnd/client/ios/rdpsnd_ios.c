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

#include "rdpsnd_main.h"

struct rdpsnd_ios_plugin
{
	rdpsndDevicePlugin device;
	
	BOOL isOpen;
	BOOL isPlaying;
	int bytesPerFrame;
	
	wBufferPool* pool;
	AUDIO_FORMAT format;
	
	wQueue* RenderQueue;
	wQueue* PendingQueue;
	
	UINT16 wPlaybackDelay;
	UINT32 inNumberBytes;
	
	CRITICAL_SECTION lock;
	AudioComponentInstance audioUnit;
};
typedef struct rdpsnd_ios_plugin rdpsndIOSPlugin;

static OSStatus rdpsnd_ios_render_notify_cb(
				      void* inRefCon,
				      AudioUnitRenderActionFlags* ioActionFlags,
				      const AudioTimeStamp* inTimeStamp,
				      UInt32 inBusNumber,
				      UInt32 inNumberFrames,
				      AudioBufferList* ioData
				      )
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) inRefCon;
	
	return noErr;
	
	if (*ioActionFlags == kAudioUnitRenderAction_PostRender)
	{
		int inNumberBytes;
		RDPSND_WAVE* wave;
		AudioBuffer* audioBuffer = &ioData->mBuffers[0];
		
		inNumberBytes = inNumberFrames * p->bytesPerFrame;
		inNumberBytes /= (p->format.nChannels / audioBuffer->mNumberChannels);
		p->inNumberBytes += inNumberBytes;
		
#if 1
		printf("AudioUnitRenderNotifyCallback: inNumberFrames: %d inNumberBytes: %d mDataByteSize: %d\n",
		       (unsigned int) inNumberFrames, inNumberBytes,
		       (unsigned int) audioBuffer->mDataByteSize);
#endif
		
		wave = Queue_Peek(p->RenderQueue);
		
		if (!wave)
			return noErr;
		
		if (p->inNumberBytes >= wave->length)
		{
			UINT32 wTimeDiff;
			UINT32 wCurrentTime;
			
			wave = Queue_Dequeue(p->RenderQueue);
			
			wCurrentTime = GetTickCount();
			wave->wLocalTimeB = wCurrentTime;
			wTimeDiff = wave->wLocalTimeB - wave->wLocalTimeA;
			wave->wTimeStampB = wave->wTimeStampA + wTimeDiff;
			
			p->device.WaveConfirm(&p->device, wave);
			
			printf("\tWaveConfirm wBlockNo: %d wTimeStampA: %d wTimeStampB: %d wTimeDiff: %d\n",
			       wave->cBlockNo, wave->wTimeStampA, wave->wTimeStampB, wTimeDiff);
			
			BufferPool_Return(p->pool, wave->data);
			p->inNumberBytes = 0;
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
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) inRefCon;
	
	if (inBusNumber != 0)
		return noErr;
	
	wave = Queue_Peek(p->PendingQueue);
	
	for (i = 0; i < ioData->mNumberBuffers; i++)
	{
		AudioBuffer* audioBuffer = &ioData->mBuffers[i];
		
		if (wave)
		{
			int waveLength = (wave->length - wave->offset);
			int mDataByteSize = audioBuffer->mDataByteSize;
			int copyLength = (waveLength > mDataByteSize) ? mDataByteSize : waveLength;
			
#if 1
			printf("AudioUnitRenderCallback: inNumberFrames: %d inNumberBytes: %d mDataByteSize: %d\n",
			       (unsigned int) inNumberFrames, copyLength,
			       (unsigned int) audioBuffer->mDataByteSize);
#endif
			
			CopyMemory(audioBuffer->mData, &(wave->data[wave->offset]), copyLength);
			audioBuffer->mDataByteSize = copyLength;
			wave->offset += copyLength;
			
			if (wave->offset >= wave->length)
			{
				wave = Queue_Dequeue(p->PendingQueue);
				Queue_Enqueue(p->RenderQueue, wave);
			}
		}
		else
		{
			*ioActionFlags |= kAudioUnitRenderAction_OutputIsSilence;
			
			audioBuffer->mDataByteSize = 0;
			AudioOutputUnitStop(p->audioUnit);
			AudioSessionSetActive(false);
			p->isPlaying = FALSE;
			
			printf("Buffer underrun!\n");
		}
	}
	
	return noErr;
}

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
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	CopyMemory(&(p->format), format, sizeof(AUDIO_FORMAT));
}

static void rdpsnd_ios_set_volume(rdpsndDevicePlugin* __unused device, UINT32 __unused value)
{
	
}

static void rdpsnd_ios_start(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;

	if (!p->isPlaying)
	{
		p->isPlaying = TRUE;
		AudioOutputUnitStart(p->audioUnit);
		AudioSessionSetActive(true);
	}
}

static void rdpsnd_ios_stop(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;

	if (p->isPlaying)
	{
		AudioSessionSetActive(false);
		AudioOutputUnitStop(p->audioUnit);
		
		p->isPlaying = FALSE;
		
		Queue_Free(p->PendingQueue);
		Queue_Free(p->RenderQueue);
		BufferPool_Free(p->pool);
	}
}

static void rdpsnd_ios_wave_play(rdpsndDevicePlugin* device, RDPSND_WAVE* wave)
{
	int length;
	BYTE* data;
	
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	data = wave->data;
	length = wave->length;
	
	wave->offset = 0;
	wave->AutoConfirm = FALSE;
	
	wave->data = (BYTE*) BufferPool_Take(p->pool, length);
	CopyMemory(wave->data, data, length);
	
	Queue_Enqueue(p->PendingQueue, wave);
	
#if 1
	printf("Enqueue: wave [cBlockNo: %02X wLocalTimeA: %d wTimeStampA: %d frames: %d]\n",
	       wave->cBlockNo,
	       wave->wLocalTimeA,
	       wave->wTimeStampA,
	       (length / p->bytesPerFrame));
#endif
	
	rdpsnd_ios_start(device);
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int latency)
{
	OSStatus status;
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	if (p->isOpen)
		return;
	
	printf("rdpsnd_ios_open\n");
	
	/* Find the output audio unit. */
	AudioComponentDescription desc;
	desc.componentManufacturer = kAudioUnitManufacturer_Apple;
	desc.componentType = kAudioUnitType_Output;
	desc.componentSubType = kAudioUnitSubType_RemoteIO;
	desc.componentFlags = 0;
	desc.componentFlagsMask = 0;
	
	AudioComponent audioComponent = AudioComponentFindNext(NULL, &desc);
	
	if (audioComponent == NULL)
		return;
	
	/* Open the audio unit. */
	status = AudioComponentInstanceNew(audioComponent, &p->audioUnit);
	
	if (status != 0)
	{
		printf("AudioComponentInstanceNew failure\n");
		return;
	}
	
	CopyMemory(&(p->format), format, sizeof(AUDIO_FORMAT));
	
	/* Set the format for the AudioUnit. */

	AudioStreamBasicDescription audioFormat = { 0 };
	
	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_ALAW:
			audioFormat.mFormatID = kAudioFormatALaw;
			break;
			
		case WAVE_FORMAT_MULAW:
			audioFormat.mFormatID = kAudioFormatULaw;
			break;
			
		case WAVE_FORMAT_PCM:
			audioFormat.mFormatID = kAudioFormatLinearPCM;
			break;
			
		default:
			break;
	}
	
	audioFormat.mSampleRate       = format->nSamplesPerSec;
	audioFormat.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
	audioFormat.mFramesPerPacket  = 1; // imminent property of the Linear PCM
	audioFormat.mChannelsPerFrame = format->nChannels;
	audioFormat.mBitsPerChannel   = format->wBitsPerSample;
	audioFormat.mBytesPerFrame    = (format->wBitsPerSample * format->nChannels) / 8;
	audioFormat.mBytesPerPacket   = format->nBlockAlign;
	
	p->bytesPerFrame = audioFormat.mBytesPerFrame;
	
	rdpsnd_print_audio_format(format);
	
	status = AudioUnitSetProperty(p->audioUnit,
				      kAudioUnitProperty_StreamFormat,
				      kAudioUnitScope_Input,
				      0,
				      &audioFormat,
				      sizeof(audioFormat));
	
	if (status != 0)
	{
		printf("Failed to set audio unit property\n");
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		return;
	}
	
	/* Register Audio Unit Render Callback */
	
	AURenderCallbackStruct callbackStruct = { 0 };
	callbackStruct.inputProc = rdpsnd_ios_render_cb;
	callbackStruct.inputProcRefCon = p;
	status = AudioUnitSetProperty(p->audioUnit,
				      kAudioUnitProperty_SetRenderCallback,
				      kAudioUnitScope_Input,
				      0,
				      &callbackStruct,
				      sizeof(callbackStruct));
	
	if (status != 0)
	{
		printf("Failed to set audio unit callback\n");
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		return;
	}
	
	/* Render Notify Callback */
	status = AudioUnitAddRenderNotify(p->audioUnit, rdpsnd_ios_render_notify_cb, p);
	
	if (status != 0)
	{
		printf("Could not register render notify callback!\n");
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		return;
	}
	
	/* Render Notify Callback */
	status = AudioUnitAddRenderNotify(p->audioUnit, rdpsnd_ios_render_notify_cb, p);
	
	if (status != 0)
	{
		printf("Could not register render notify callback!\n");
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		return;
	}
	
	/* Initialize the AudioUnit. */
	status = AudioUnitInitialize(p->audioUnit);
	
	if (status != 0)
	{
		printf("Failed to init the Audio Unit\n");
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		return;
	}
	
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
	
	UInt32 bufferLengthInFrames = ((hardwareSampleRate * hardwareBufferDuration) + 0.5) / hardwareOutputNumberChannels;
	
	printf("buffer length in frames: %d\n", (int) bufferLengthInFrames);
	printf("kAudioSessionProperty_CurrentHardwareSampleRate: %f\n", hardwareSampleRate);
	printf("kAudioSessionProperty_CurrentHardwareIOBufferDuration: %f\n", hardwareBufferDuration);
	printf("kAudioSessionProperty_CurrentHardwareOutputNumberChannels: %d\n", (int) hardwareOutputNumberChannels);
	
	status = AudioSessionSetActive(true);
	
	p->isOpen = TRUE;
	
	InitializeCriticalSectionAndSpinCount(&(p->lock), 4000);
	
	p->RenderQueue = Queue_New(TRUE, 0, 0);
	p->PendingQueue = Queue_New(TRUE, 0, 0);
	
	p->pool = BufferPool_New(TRUE, -1, 0);
	
	/* audio buffer latency */
	
	Float64 latency64 = 0;
	UInt32 dataSize = sizeof(Float64);
	
	status = AudioUnitGetProperty(p->audioUnit,
				      kAudioUnitProperty_Latency,
				      kAudioUnitScope_Global,
				      0,
				      &latency64,
				      &dataSize);
	
	if (status != 0)
	{
		printf("AudioUnitGetProperty: failed to query kAudioUnitProperty_Latency\n");
	}
	
	printf("audio unit latency: %.06fms\n", latency64 * 1000.0);
	
	p->wPlaybackDelay = (UINT16) (latency64 * 1000.0);
}

static void rdpsnd_ios_close(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	printf("rdpsnd_ios_close\n");
	
	/* Make sure the device is stopped. */
	rdpsnd_ios_stop(device);
	
	if (p->isOpen)
	{
		/* Close the device. */
		AudioUnitUninitialize(p->audioUnit);
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		p->isOpen = FALSE;
	}
}

static void rdpsnd_ios_free(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	/* Ensure the device is closed. */
	rdpsnd_ios_close(device);
	
	/* Free memory associated with the device. */
	free(p);
}

#ifdef STATIC_CHANNELS
#define freerdp_rdpsnd_client_subsystem_entry	ios_freerdp_rdpsnd_client_subsystem_entry
#endif

int freerdp_rdpsnd_client_subsystem_entry(PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) malloc(sizeof(rdpsndIOSPlugin));
	
	if (p)
	{
		ZeroMemory(p, sizeof(rdpsndIOSPlugin));
	
		p->device.Open = rdpsnd_ios_open;
		p->device.FormatSupported = rdpsnd_ios_format_supported;
		p->device.SetFormat = rdpsnd_ios_set_format;
		p->device.SetVolume = rdpsnd_ios_set_volume;
		p->device.Start = rdpsnd_ios_start;
		p->device.Close = rdpsnd_ios_close;
		p->device.Free = rdpsnd_ios_free;
		p->device.WavePlay = rdpsnd_ios_wave_play;
	
		pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) p);
	}
	
	return 0;
}
