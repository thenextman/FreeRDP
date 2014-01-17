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

#import <pthread.h>
#import <mach/mach_time.h>
#import <libkern/OSAtomic.h>

#import <AudioToolbox/AudioToolbox.h>
#import <AudioToolbox/AudioQueue.h>

#include "rdpsnd_main.h"

#define IOS_AUDIO_NUM_BUFFERS	8
#define IOS_AUDIO_BUFFER_SIZE	32768

extern void rdpsnd_send_wave_confirm_pdu(rdpsndPlugin* rdpsnd, UINT16 wTimeStamp, BYTE cConfirmedBlockNo);

#define IOS_AUDIO_BLOCK_STATE_NULL		0x00000000
#define IOS_AUDIO_BLOCK_STATE_PENDING		0x00000001
#define IOS_AUDIO_BLOCK_STATE_ENQUEUED		0x00000002
#define IOS_AUDIO_BLOCK_STATE_CONFIRMED		0x00000003

struct _IOS_AUDIO_BLOCK
{
	BOOL bValid;
	UINT16 wTimeStamp;
	UINT16 wAudioLength;
	UInt64 mMachTimeA;
	UInt64 mMachTimeB;
	RDPSND_WAVE* wave;
};
typedef struct _IOS_AUDIO_BLOCK IOS_AUDIO_BLOCK;

struct rdpsnd_ios_plugin
{
	rdpsndDevicePlugin device;
	
	BOOL isOpen;
	BOOL isPlaying;
	BOOL isRunning;
	
	AUDIO_FORMAT format;
	
	__attribute__((aligned(8))) int64_t cBlockNo;
	__attribute__((aligned(8))) int64_t cConfirmedBlockNo;
		
	IOS_AUDIO_BLOCK audioBlocks[256];
	
	wQueue* waveQueue;
	wQueue* audioBufferQueue;
	
	pthread_t thread;
	pthread_attr_t attr;
	struct sched_param param;
	
	CRITICAL_SECTION lock;
	BOOL isAudioSessionInitialized;
	AudioStreamBasicDescription audioFormat;
	
	int audioQueueSize;
	AudioQueueRef audioQueue;
	AudioQueueBufferRef audioBuffers[IOS_AUDIO_NUM_BUFFERS];
};
typedef struct rdpsnd_ios_plugin rdpsndIOSPlugin;

static double machTimeFactorNano = 1.0;
static mach_timebase_info_data_t machTimebaseInfo = { 0, 0 };

UINT32 mach_time_to_milliseconds(UInt64 machTime)
{
	if ((machTimebaseInfo.denom == 0) && (machTimebaseInfo.numer == 0))
	{
		mach_timebase_info(&machTimebaseInfo);
		machTimeFactorNano = (double) machTimebaseInfo.numer / machTimebaseInfo.denom;
	}
	
	return (UINT32) (((UInt64) (machTime * machTimeFactorNano)) / 1000000);
}

UInt64 milliseconds_to_mach_time(UINT32 milliTime)
{
	if ((machTimebaseInfo.denom == 0) && (machTimebaseInfo.numer == 0))
	{
		mach_timebase_info(&machTimebaseInfo);
		machTimeFactorNano = (double) machTimebaseInfo.numer / machTimebaseInfo.denom;
	}
	
	return (UInt64) ((double) ((UInt64) milliTime * 1000000) / machTimeFactorNano);
}

int ios_audio_confirm_pending_blocks(rdpsndIOSPlugin* ios, BOOL flush)
{
	int count;
	BYTE cBlockNo;
	UInt64 mMachTime;
	UINT16 wTimeDiff;
	UINT16 wTimeDelta;
	UINT16 wTimeStamp;
	IOS_AUDIO_BLOCK* pBlock;
	
	count = 0;
	mMachTime = mach_absolute_time();
	
	cBlockNo = ios->cConfirmedBlockNo % 256;
	pBlock = &(ios->audioBlocks[cBlockNo]);
	
	while (pBlock->bValid)
	{
		if ((mMachTime >= pBlock->mMachTimeB) || flush)
		{
			wTimeDiff = (UINT16) mach_time_to_milliseconds(pBlock->mMachTimeB - pBlock->mMachTimeA);
			wTimeDelta = (UINT16) mach_time_to_milliseconds(mMachTime - pBlock->mMachTimeA);
			
			if (!flush)
				wTimeStamp = pBlock->wTimeStamp + wTimeDiff;
			else
				wTimeStamp = pBlock->wTimeStamp + wTimeDelta;
			
			printf("WaveConfirm: cBlockNo: %d wTimeDiff: %d wTimeDelta: %d offset: %d\n",
				cBlockNo, wTimeDiff, wTimeDelta, wTimeDelta - wTimeDiff);
			
			rdpsnd_send_wave_confirm_pdu(ios->device.rdpsnd, wTimeStamp, cBlockNo);
			
			ZeroMemory(pBlock, sizeof(IOS_AUDIO_BLOCK));
			
			OSAtomicIncrement64Barrier(&(ios->cConfirmedBlockNo));
			cBlockNo = ios->cConfirmedBlockNo % 256;
		}
		else
		{
			break;
		}
		
		pBlock = &(ios->audioBlocks[cBlockNo]);
	}
	
	return 0;
}

static void* ios_audio_thread(void* arg)
{
	UInt64 mMachTime;
	UInt64 mMachInterval;
	
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) arg;
	
	mMachInterval = milliseconds_to_mach_time(10);
	
	while (1)
	{
		mMachTime = mach_absolute_time();
		
		mach_wait_until(mMachTime + mMachInterval);
		
		ios_audio_confirm_pending_blocks(ios, FALSE);
	}
	
	return NULL;
}

static int ios_audio_enqueue_buffer(rdpsndIOSPlugin* ios, RDPSND_WAVE* wave, AudioQueueBufferRef inBuffer)
{
	BYTE cBlockNo;
	OSStatus status;
	UInt64 machAudioLength;
	IOS_AUDIO_BLOCK* pBlock;
	
	cBlockNo = wave->cBlockNo;
	inBuffer->mAudioDataByteSize = wave->length;
	CopyMemory(inBuffer->mAudioData, wave->data, wave->length);
	free(wave->data);
	free(wave);
	
	AudioTimeStamp inStartTime;
	AudioTimeStamp outActualStartTime;
	
	ZeroMemory(&inStartTime, sizeof(AudioTimeStamp));
	
	status = AudioQueueEnqueueBufferWithParameters(ios->audioQueue, inBuffer, 0, NULL,
						       0, 0, 0, NULL, NULL, &outActualStartTime);
	
	if (status != 0)
	{
		printf("AudioQueueEnqueueBufferWithParameters failure\n");
	}
	
	if (!(outActualStartTime.mFlags & kAudioTimeStampHostTimeValid))
	{
		outActualStartTime.mHostTime = mach_absolute_time();
	}
	
	pBlock = &(ios->audioBlocks[cBlockNo]);
	
	machAudioLength = milliseconds_to_mach_time(pBlock->wAudioLength);
	pBlock->mMachTimeB = outActualStartTime.mHostTime + machAudioLength;
	pBlock->bValid = TRUE;
	
	OSAtomicIncrement64Barrier(&(ios->cBlockNo));
	
	return 0;
}

static void ios_audio_queue_output_cb(void* inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer)
{
	RDPSND_WAVE* wave;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) inUserData;
	
	wave = (RDPSND_WAVE*) Queue_Dequeue(ios->waveQueue);
	
	if (!ios->isOpen)
		return;
	
	if (wave)
	{
		if (inBuffer->mAudioDataBytesCapacity < wave->length)
		{
			fprintf(stderr, "ios_audio_queue_output_cb: error: audio queue buffer capacity exceeded\n");
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
	
	Float32 preferredHardwareIOBufferDuration = 1.0; /* seconds */
	propertySize = sizeof(preferredHardwareIOBufferDuration);
	
	status = AudioSessionSetProperty(kAudioSessionProperty_PreferredHardwareIOBufferDuration, propertySize, &preferredHardwareIOBufferDuration);
	
	if (status != 0)
	{
		printf("AudioSessionSetProperty failed kAudioSessionProperty_PreferredHardwareIOBufferDuration\n");
	}
	
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
	else if (format->wFormatTag == WAVE_FORMAT_GSM610)
	{
		return FALSE;
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
			
		case WAVE_FORMAT_GSM610:
			ios->audioFormat.mFormatID = kAudioFormatMicrosoftGSM;
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
	BYTE* data;
	IOS_AUDIO_BLOCK* pBlock;
	AudioQueueBufferRef audioBuffer;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	pBlock = &(ios->audioBlocks[wave->cBlockNo]);
	
	ZeroMemory(pBlock, sizeof(IOS_AUDIO_BLOCK));
	
	pBlock->wTimeStamp = wave->wTimeStampA;
	pBlock->wAudioLength = wave->wAudioLength;
	pBlock->mMachTimeA = mach_absolute_time();
	pBlock->wave = wave;
	
	wave->AutoConfirm = FALSE;
	
	data = wave->data;
	wave->data = (BYTE*) malloc(wave->length);
	CopyMemory(wave->data, data, wave->length);
	
	OSAtomicIncrement64Barrier(&(ios->cBlockNo));
	
	audioBuffer = Queue_Dequeue(ios->audioBufferQueue);
	
	if (audioBuffer)
	{
		ios_audio_enqueue_buffer(ios, wave, audioBuffer);
	}
	else
	{
		Queue_Enqueue(ios->waveQueue, wave);
	}
	
	rdpsnd_ios_start(device);
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int __unused latency)
{
	int index;
	OSStatus status;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	if (ios->isOpen)
		return;
	
	printf("rdpsnd_ios_open\n");
	
	ios->cBlockNo = 0;
	ios->cConfirmedBlockNo = 0;
	
	ios_audio_session_set_properties(ios);
	
	device->SetFormat(device, format, 0);
	
	status = AudioQueueNewOutput(&(ios->audioFormat),
				 ios_audio_queue_output_cb, ios,
				 NULL, NULL, 0, &(ios->audioQueue));
	
	if (status != 0)
	{
		printf("AudioQueueNewOutput failure\n");
		return;
	}
	
	status = AudioQueueAddPropertyListener(ios->audioQueue,
					       kAudioQueueProperty_IsRunning,
					       ios_audio_queue_property_listener_is_running_cb, ios);
	
	if (status != 0)
	{
		printf("AudioQueueAddPropertyListener IsRunning failure\n");
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
	
	ios->audioBufferQueue = Queue_New(TRUE, 0, 0);
	
	for (index = 0; index < IOS_AUDIO_NUM_BUFFERS; index++)
	{
		status = AudioQueueAllocateBuffer(ios->audioQueue, IOS_AUDIO_BUFFER_SIZE, &(ios->audioBuffers[index]));
	
		if (status != 0)
		{
			printf("AudioQueueAllocateBuffer failed\n");
		}
		else
		{
			Queue_Enqueue(ios->audioBufferQueue, ios->audioBuffers[index]);
		}
	}
	
	ios->isOpen = TRUE;
}

static void rdpsnd_ios_close(rdpsndDevicePlugin* device)
{
	int index;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	printf("rdpsnd_ios_close\n");
	
	if (ios->isOpen)
	{
		ios->isOpen = FALSE;
		
		AudioQueueStop(ios->audioQueue, true);
		
		AudioQueueRemovePropertyListener(ios->audioQueue, kAudioQueueProperty_IsRunning,
						 ios_audio_queue_property_listener_is_running_cb, ios);
		
		for (index = 0; index < IOS_AUDIO_NUM_BUFFERS; index++)
		{
			AudioQueueFreeBuffer(ios->audioQueue, ios->audioBuffers[index]);
		}
		
		Queue_Free(ios->audioBufferQueue);
		
		AudioQueueDispose(ios->audioQueue, true);

		ios->audioQueue = NULL;
		
		ios_audio_confirm_pending_blocks(ios, TRUE);
		
		ios->isPlaying = FALSE;
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
		
		ios->device.DisableConfirmThread = TRUE;
		
		InitializeCriticalSectionAndSpinCount(&(ios->lock), 4000);
		
		pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) ios);
		
		pthread_attr_init(&ios->attr);
		ios->param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		pthread_attr_setschedparam(&ios->attr, &ios->param);
		pthread_attr_setschedpolicy(&ios->attr, SCHED_FIFO);
		pthread_create(&ios->thread, &ios->attr, ios_audio_thread, (void*) ios);
	}
	
	return 0;
}
