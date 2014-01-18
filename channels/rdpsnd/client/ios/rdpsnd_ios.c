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

extern void rdpsnd_send_wave_confirm_pdu(rdpsndPlugin* rdpsnd, UINT16 wTimeStamp, BYTE cConfirmedBlockNo);

struct _AudioQueueNode
{
	BOOL bSilence;
	int64_t cBlockNo;
	AudioQueueBufferRef buffer;
};
typedef struct _AudioQueueNode AudioQueueNode;

struct _IOS_AUDIO_BLOCK
{
	BOOL bValid;
	UINT16 wTimeStamp;
	UINT16 wAudioLength;
	UInt64 mMachTimeA;
	UInt64 mMachTimeB;
};
typedef struct _IOS_AUDIO_BLOCK IOS_AUDIO_BLOCK;

struct rdpsnd_ios_plugin
{
	rdpsndDevicePlugin device;
	
	BOOL isOpen;
	BOOL isPlaying;
	BOOL isRunning;
	
	AUDIO_FORMAT format;
	UInt64 mPlaybackTime;
	
	__attribute__((aligned(8))) int64_t cBlockNo;
	__attribute__((aligned(8))) int64_t cConfirmedBlockNo;
		
	IOS_AUDIO_BLOCK audioBlocks[256];
	
	wQueue* queue;
	HANDLE runningEvent;
	
	pthread_t thread;
	pthread_attr_t attr;
	struct sched_param param;
	
	pthread_mutex_t mutex_confirm;
	pthread_cond_t cond_confirm;
	
	CRITICAL_SECTION lock;
	BOOL isAudioSessionInitialized;
	AudioStreamBasicDescription audioFormat;
	
	AudioQueueRef audioQueue;
	AudioQueueTimelineRef audioTimeline;
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
	UInt64 mWaitEndTime;
	IOS_AUDIO_BLOCK* pBlock;
	
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) arg;
	
	while (1)
	{
		pthread_mutex_lock(&ios->mutex_confirm);
		
		pthread_cond_wait(&ios->cond_confirm, &ios->mutex_confirm);
		
		pBlock = &(ios->audioBlocks[ios->cConfirmedBlockNo % 256]);
		mWaitEndTime = pBlock->mMachTimeB;
		
		pthread_mutex_unlock(&ios->mutex_confirm);
		
		mach_wait_until(mWaitEndTime);
		
		ios_audio_confirm_pending_blocks(ios, FALSE);
	}
	
	return NULL;
}

static void ios_audio_queue_output_cb(void* inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer)
{
	BOOL underrun;
	OSStatus status;
	AudioQueueNode* node;
	rdpsndIOSPlugin* ios;
	IOS_AUDIO_BLOCK* pBlock;
	
	ios = (rdpsndIOSPlugin*) inUserData;
	node = inBuffer->mUserData;
	
	if (!node)
	{
		AudioQueueFreeBuffer(inAQ, inBuffer);
		return;
	}
	
	pBlock = &(ios->audioBlocks[node->cBlockNo % 256]);
	underrun = (node->cBlockNo == ios->cBlockNo) ? TRUE : FALSE;
	
	if (underrun)
	{
		printf("Buffer underrun!\n");
		
		inBuffer->mAudioDataByteSize = inBuffer->mAudioDataBytesCapacity;
		ZeroMemory(inBuffer->mAudioData, inBuffer->mAudioDataBytesCapacity);
		
		node->bSilence = TRUE;
		
		status = AudioQueueEnqueueBufferWithParameters(inAQ, inBuffer, 0, NULL,
							       0, 0, 0, NULL, NULL, NULL);
		
		if (status != 0)
		{
			printf("AudioQueueEnqueueBufferWithParameters failure\n");
		}
	}
	else
	{
#if 0
		pthread_mutex_lock(&ios->mutex_confirm);
		pthread_cond_signal(&ios->cond_confirm);
		pthread_mutex_unlock(&ios->mutex_confirm);
#endif
		
		AudioQueueFreeBuffer(inAQ, inBuffer);
		free(node);
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
		
		SetEvent(ios->runningEvent);
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
		AudioQueueBufferRef buffer;
		
		if (!ios->audioQueue)
			return;
		
		AudioQueueAllocateBuffer(ios->audioQueue, 2048, &(buffer));
		
		buffer->mAudioDataByteSize = 2048;
		ZeroMemory(buffer->mAudioData, 2048);
		buffer->mUserData = NULL;
		
		status = AudioQueueEnqueueBufferWithParameters(ios->audioQueue, buffer, 0, NULL,
							       0, 0, 0, NULL, NULL, NULL);
		
		ResetEvent(ios->runningEvent);
		
		status = AudioQueueStart(ios->audioQueue, NULL);
		
		if (status != 0)
		{
			printf("AudioQueueStart failed\n");
		}
		
		WaitForSingleObject(ios->runningEvent, INFINITE);
		
		ios->isPlaying = TRUE;
	}
}

static void rdpsnd_ios_wave_play(rdpsndDevicePlugin* device, RDPSND_WAVE* wave)
{
	OSStatus status;
	UINT16 wTimeDiff;
	AudioQueueNode* node;
	UInt64 machAudioLength;
	IOS_AUDIO_BLOCK* pBlock;
	AudioTimeStamp inStartTime;
	AudioTimeStamp outActualStartTime;
	rdpsndIOSPlugin* ios = (rdpsndIOSPlugin*) device;
	
	/* https://developer.apple.com/library/ios/qa/qa1643/_index.html */
	
	if (wave->cBlockNo != (ios->cBlockNo % 256))
	{
		printf("out of sequence block number: actual: %d expected: %d\n",
		       wave->cBlockNo, (int) (ios->cBlockNo % 256));
		return;
	}
	
	device->Start(device);
	
	node = (AudioQueueNode*) malloc(sizeof(AudioQueueNode));
	ZeroMemory(node, sizeof(AudioQueueNode));
	
	node->cBlockNo = ios->cBlockNo;
	AudioQueueAllocateBuffer(ios->audioQueue, wave->length, &(node->buffer));
	
	node->buffer->mAudioDataByteSize = wave->length;
	CopyMemory(node->buffer->mAudioData, wave->data, wave->length);
	node->buffer->mUserData = (void*) node;
	
	AudioTimeStamp outTimeStamp;
	Boolean outTimelineDiscontinuity = false;
	
	status = AudioQueueGetCurrentTime(ios->audioQueue,
					  ios->audioTimeline,
					  &outTimeStamp,
					  &outTimelineDiscontinuity);
	
	if (status != 0)
	{
		printf("AudioQueueGetCurrentTime failure\n");
	}
	
	if (outTimelineDiscontinuity)
	{
		printf("Timeline discontinuity detected!\n");
	}
	
	if (!(outTimeStamp.mFlags & kAudioTimeStampHostTimeValid))
	{
		printf("AudioQueueGetCurrentTime invalid host time\n");
		outTimeStamp.mHostTime = mach_absolute_time();
	}
	
	ZeroMemory(&inStartTime, sizeof(AudioTimeStamp));
	
	inStartTime.mFlags = kAudioTimeStampHostTimeValid;
	inStartTime.mHostTime = mach_absolute_time();
	
	status = AudioQueueEnqueueBufferWithParameters(ios->audioQueue, node->buffer, 0, NULL,
						       0, 0, 0, NULL, &inStartTime, &outActualStartTime);
	
	if (status != 0)
	{
		printf("AudioQueueEnqueueBufferWithParameters failure\n");
	}
	
	if (!(outActualStartTime.mFlags & kAudioTimeStampHostTimeValid))
	{
		outActualStartTime.mHostTime = mach_absolute_time();
	}
	
	pBlock = &(ios->audioBlocks[node->cBlockNo % 256]);
	ZeroMemory(pBlock, sizeof(IOS_AUDIO_BLOCK));
	
	pBlock->wTimeStamp = wave->wTimeStampA;
	pBlock->wAudioLength = wave->wAudioLength;
	pBlock->mMachTimeA = mach_absolute_time();
	
	machAudioLength = milliseconds_to_mach_time(pBlock->wAudioLength);
	pBlock->mMachTimeB = outActualStartTime.mHostTime + machAudioLength;
	pBlock->bValid = TRUE;
	
	wTimeDiff = (UINT16) mach_time_to_milliseconds(pBlock->mMachTimeB - pBlock->mMachTimeA);
	
	wave->wTimeStampB = wave->wTimeStampA + wTimeDiff;
	wave->wLocalTimeB = wave->wLocalTimeA + wTimeDiff;
	
	printf("wTimeDiff: %d cBlockNo: %d\n", wTimeDiff, wave->cBlockNo);
	
	OSAtomicIncrement64Barrier(&(ios->cBlockNo));
	
	//wave->AutoConfirm = FALSE;
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int __unused latency)
{
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
		ios->isOpen = FALSE;
		
		AudioQueueStop(ios->audioQueue, true);
		
		AudioQueueDisposeTimeline(ios->audioQueue, ios->audioTimeline);
		
		AudioQueueRemovePropertyListener(ios->audioQueue, kAudioQueueProperty_IsRunning,
						 ios_audio_queue_property_listener_is_running_cb, ios);
		
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
			
		ios->queue = Queue_New(TRUE, 0, 0);
		ios->runningEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		
		//ios->device.DisableConfirmThread = TRUE;
		
		InitializeCriticalSectionAndSpinCount(&(ios->lock), 4000);
		
		pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) ios);
		
		pthread_cond_init(&ios->cond_confirm, NULL);
		pthread_mutex_init(&ios->mutex_confirm, NULL);
		
#if 0
		pthread_attr_init(&ios->attr);
		ios->param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		pthread_attr_setschedparam(&ios->attr, &ios->param);
		pthread_attr_setschedpolicy(&ios->attr, SCHED_FIFO);
		pthread_create(&ios->thread, &ios->attr, ios_audio_thread, (void*) ios);
#endif
	}
	
	return 0;
}
