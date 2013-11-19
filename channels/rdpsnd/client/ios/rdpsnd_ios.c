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

#include <mach/mach_time.h>

#import <AudioToolbox/AudioToolbox.h>
#import <AudioToolbox/AudioQueue.h>

#include "rdpsnd_main.h"

struct rdpsnd_ios_plugin
{
	rdpsndDevicePlugin device;
	
	BOOL isOpen;
	BOOL isPlaying;
	BOOL isRunning;
	
	UINT32 cBlockNo;
	AUDIO_FORMAT format;
	UINT32 wBufferedTime;
	
	wQueue* waveQueue;
	
	CRITICAL_SECTION lock;
	BOOL isAudioSessionInitialized;
	AudioStreamBasicDescription audioFormat;
	
	int audioQueueSize;
	AudioQueueRef audioQueue;
	AudioQueueBufferRef audioBuffer;
	AudioQueueTimelineRef audioTimeline;
};
typedef struct rdpsnd_ios_plugin rdpsndIOSPlugin;

static mach_timebase_info_data_t machTimebaseInfo = { 0, 0 };

UInt64 ios_absolute_to_nanoseconds(UInt64 absoluteTime)
{
	UInt64 nanoTime;
	
	if ((machTimebaseInfo.denom == 0) && (machTimebaseInfo.numer == 0))
		mach_timebase_info(&machTimebaseInfo);
	
	nanoTime = absoluteTime * machTimebaseInfo.numer / machTimebaseInfo.denom;
	
	return nanoTime;
}

static int ios_audio_enqueue_buffer(rdpsndIOSPlugin* ios, RDPSND_WAVE* wave, AudioQueueBufferRef inBuffer)
{
	OSStatus status;
	UINT32 wTimeDiff;
	
	inBuffer->mAudioDataByteSize = wave->length;
	CopyMemory(inBuffer->mAudioData, wave->data, wave->length);
	free(wave->data);
	
	AudioTimeStamp inStartTime;
	AudioTimeStamp outActualStartTime;
	
	ZeroMemory(&inStartTime, sizeof(AudioTimeStamp));
	inStartTime.mSampleTime = ((Float64) ios->wBufferedTime) * 1000.0;
	
	ios->wBufferedTime += wave->wAudioLength;
	
	status = AudioQueueEnqueueBufferWithParameters(ios->audioQueue, inBuffer, 0, NULL,
						       0, 0, 0, NULL, NULL, &outActualStartTime);
	
	if (status != 0)
	{
		printf("AudioQueueEnqueueBufferWithParameters failure\n");
	}
	
	UINT32 mStartTime = (UINT32) (outActualStartTime.mSampleTime / 1000.0);
	
	if (ios->isRunning)
	{
		AudioTimeStamp outTimeStamp;
		Boolean outTimelineDiscontinuity = false;
		
		UInt64 absTime = mach_absolute_time();
		
		status = AudioQueueGetCurrentTime(ios->audioQueue,
						  ios->audioTimeline,
						  &outTimeStamp,
						  &outTimelineDiscontinuity);
		
		if (status != 0)
		{
			printf("AudioQueueGetCurrentTime failure\n");
		}
		
		if (outTimelineDiscontinuity)
			printf("Timeline discontinuity detected!\n");
		
		UInt64 deltaHostTime = outTimeStamp.mHostTime - absTime;
		UINT32 deltaTime = (UINT32) (ios_absolute_to_nanoseconds(deltaHostTime) / 1000.0);
		wTimeDiff = deltaTime - mStartTime;
		
		wTimeDiff = deltaTime + wave->wAudioLength;
	}
	else
	{
		wTimeDiff = mStartTime + wave->wAudioLength;
	}
	
	wave->wLocalTimeB = wave->wLocalTimeA + wTimeDiff;
	wave->wTimeStampB = wave->wTimeStampA + wTimeDiff;
	
	if (ios->cBlockNo == wave->cBlockNo)
	{
		ios->device.WaveConfirm(&(ios->device), wave);
		ios->cBlockNo = (ios->cBlockNo + 1) % 256;
	}
	else
	{
		printf("warning: out of order cBlockNo: %d, expected %d\n", wave->cBlockNo, ios->cBlockNo);
	}
	
	return 0;
}

static void ios_audio_queue_output_cb(void* inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer)
{
	//HANDLE event;
	RDPSND_WAVE* wave;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inUserData;
	
	//event = Queue_Event(ios->waveQueue);
	
	//WaitForSingleObject(event, 400);
	
	wave = (RDPSND_WAVE*) Queue_Dequeue(ios->waveQueue);
	
	if (wave)
	{
		if (inBuffer->mAudioDataBytesCapacity < wave->length)
		{
			OSStatus status;
			
			status = AudioQueueAllocateBuffer(ios->audioQueue, wave->length, &(ios->audioBuffer));
			
			if (status != 0)
			{
				printf("AudioQueueAllocateBuffer failed\n");
			}
			
			inBuffer = ios->audioBuffer;
		}
		
		ios_audio_enqueue_buffer(ios, wave, inBuffer);	
	}
	else
	{
		OSStatus status;
	
		printf("Buffer underrun\n");
		
		inBuffer->mAudioDataByteSize = inBuffer->mAudioDataBytesCapacity;
		ZeroMemory(inBuffer->mAudioData, inBuffer->mAudioDataBytesCapacity);
		
		status = AudioQueueEnqueueBufferWithParameters(ios->audioQueue, inBuffer, 0, NULL,
							       0, 0, 0, NULL, NULL, NULL);
		
		if (status != 0)
		{
			printf("AudioQueueEnqueueBufferWithParameters failure\n");
		}
		
		//AudioQueueStop(inAQ, TRUE);
		//ios->isPlaying = FALSE;
	}
}

static void ios_audio_queue_property_listener_is_running_cb(void* inUserData, AudioQueueRef inAQ, AudioQueuePropertyID inID)
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
	}
}

static void ios_audio_queue_property_listener_converter_error_cb(void* inUserData, AudioQueueRef inAQ, AudioQueuePropertyID inID)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inUserData;
	
	if (inID == kAudioQueueProperty_ConverterError)
	{
		OSStatus status;
		UInt32 propertySize;
		
		UInt32 converterError;
		propertySize = sizeof(converterError);
		
		status = AudioQueueGetProperty(ios->audioQueue,
					       kAudioQueueProperty_ConverterError,
					       &converterError,
					       &propertySize);
		
		if (status != 0)
		{
			printf("AudioQueueGetProperty failure: kAudioQueueProperty_ConverterError\n");
		}
		
		printf("kAudioQueueProperty_ConverterError: %d\n", (int) converterError);
	}
}

void ios_audio_session_set_properties(rdpsndIOSPlugin* ios)
{
	OSStatus status;
	UInt32 propertySize;
	
	if (!ios->isAudioSessionInitialized)
	{
		status = AudioSessionInitialize(NULL, NULL, NULL, NULL);
		
		if (status != 0)
		{
			printf("AudioSessionInitialize failed\n");
		}
		
		ios->isAudioSessionInitialized = TRUE;
	}
	
#if 1
	Float32 preferredHardwareIOBufferDuration = 1.0; /* seconds */
	propertySize = sizeof(preferredHardwareIOBufferDuration);
	
	status = AudioSessionSetProperty(kAudioSessionProperty_PreferredHardwareIOBufferDuration, propertySize, &preferredHardwareIOBufferDuration);
	
	if (status != 0)
	{
		printf("AudioSessionSetProperty failed kAudioSessionProperty_PreferredHardwareIOBufferDuration\n");
	}
#endif
	
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
		
		if (!ios->audioQueue)
			return;
		
		status = AudioQueueStart(ios->audioQueue, NULL);
		
		if (status != 0)
		{
			printf("AudioQueueStart failed\n");
		}
		
		ios->isPlaying = TRUE;
	}
}

static void rdpsnd_ios_wave_play(rdpsndDevicePlugin* device, RDPSND_WAVE* wave)
{
	int length;
	BYTE* data;
	OSStatus status;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	data = wave->data;
	length = wave->length;
	wave->AutoConfirm = FALSE;
	
	wave->data = (BYTE*) malloc(length);
	CopyMemory(wave->data, data, length);
	
	if (!ios->audioBuffer)
	{
		status = AudioQueueAllocateBuffer(ios->audioQueue, wave->length, &(ios->audioBuffer));
	
		if (status != 0)
		{
			printf("AudioQueueAllocateBuffer failed\n");
		}
		
		ios_audio_enqueue_buffer(ios, wave, ios->audioBuffer);
	}
	else
	{
		Queue_Enqueue(ios->waveQueue, wave);
	}
	
	rdpsnd_ios_start(device);
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int latency)
{
	OSStatus status;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	if (ios->isOpen)
		return;
	
	printf("rdpsnd_ios_open\n");
	
	ios_audio_session_set_properties(ios);
	
	device->SetFormat(device, format, 200);
	
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
	
	status = AudioQueueAddPropertyListener(ios->audioQueue,
					       kAudioQueueProperty_IsRunning,
					       ios_audio_queue_property_listener_is_running_cb, ios);
	
	if (status != 0)
	{
		printf("AudioQueueAddPropertyListener IsRunning failure\n");
	}
	
	status = AudioQueueAddPropertyListener(ios->audioQueue,
					       kAudioQueueProperty_ConverterError,
					       ios_audio_queue_property_listener_converter_error_cb, ios);
	
	if (status != 0)
	{
		printf("AudioQueueAddPropertyListener ConverterError failure\n");
	}
	
	UInt32 DecodeBufferSizeFrames;
	UInt32 propertySize = sizeof(DecodeBufferSizeFrames);
	
	AudioQueueGetProperty(ios->audioQueue,
			      kAudioQueueProperty_DecodeBufferSizeFrames,
			      &DecodeBufferSizeFrames,
			      &propertySize);
	
	if (status != 0)
	{
		printf("AudioQueueGetProperty failure: kAudioQueueProperty_DecodeBufferSizeFrames\n");
	}
	
	printf("kAudioQueueProperty_DecodeBufferSizeFrames: %d\n", (int) DecodeBufferSizeFrames);

	ios->isOpen = TRUE;
}

static void rdpsnd_ios_close(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	printf("rdpsnd_ios_close\n");
	
	if (ios->isOpen)
	{
		AudioQueueStop(ios->audioQueue, true);
		
		AudioQueueDisposeTimeline(ios->audioQueue, ios->audioTimeline);
		
		AudioQueueRemovePropertyListener(ios->audioQueue, kAudioQueueProperty_IsRunning,
						 ios_audio_queue_property_listener_is_running_cb, ios);
		
		AudioQueueRemovePropertyListener(ios->audioQueue, kAudioQueueProperty_ConverterError,
						 ios_audio_queue_property_listener_converter_error_cb, ios);
		
		AudioQueueDispose(ios->audioQueue, true);

		ios->audioQueue = NULL;
		ios->audioTimeline = NULL;
		ios->audioQueueSize = 0;
		ios->wBufferedTime = 0;
		
		ios->isPlaying = FALSE;
		ios->isOpen = FALSE;
	}
}

static void rdpsnd_ios_free(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	rdpsnd_ios_close(device);

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
	
		ios->waveQueue = Queue_New(TRUE, 0, 0);
		
		InitializeCriticalSectionAndSpinCount(&(ios->lock), 4000);
		
		pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) ios);
	}
	
	return 0;
}
