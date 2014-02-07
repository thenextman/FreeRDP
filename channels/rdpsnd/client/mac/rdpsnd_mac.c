/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Audio Output Virtual Channel
 *
 * Copyright 2012 Laxmikant Rashinkar <LK.Rashinkar@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/sysinfo.h>

#include <freerdp/types.h>
#include <freerdp/codec/dsp.h>
#include <freerdp/utils/svc_plugin.h>

#include <mach/mach_time.h>

#include <AudioToolbox/AudioToolbox.h>
#include <AudioToolbox/AudioQueue.h>

#include "rdpsnd_main.h"

typedef struct rdpsnd_mac_plugin rdpsndMacPlugin;

struct mac_audio_apc_data
{
	int cBlockNo;
	DWORD DueTime;
	UINT64 wTimeStampA;
	UINT64 mTimeStampA;
	rdpsndMacPlugin* mac;
};
typedef struct mac_audio_apc_data MAC_AUDIO_APC_DATA;

struct rdpsnd_mac_plugin
{
	rdpsndDevicePlugin device;

	BOOL isOpen;
	BOOL isPlaying;
	
	UINT32 latency;
	AUDIO_FORMAT format;
	int audioBufferIndex;
	
	HANDLE hTimerQueue;
	HANDLE hTimers[256];
	MAC_AUDIO_APC_DATA apcData[256];
	
	AudioQueueRef audioQueue;
	AudioStreamBasicDescription audioFormat;
};

extern void rdpsnd_send_wave_confirm_pdu(rdpsndPlugin* rdpsnd, UINT16 wTimeStamp, BYTE cConfirmedBlockNo);

static double machTimeFactorNano = 1.0;
static mach_timebase_info_data_t machTimebaseInfo = { 0, 0 };

UINT64 mach_time_to_milliseconds(UINT64 machTime)
{
	return ((UINT64) ((machTime / 1000000) * machTimeFactorNano));
}

UINT64 milliseconds_to_mach_time(UINT64 milliTime)
{
	return (UINT64) ((double) ((UINT64) milliTime * 1000000) / machTimeFactorNano);
}

static void mac_audio_queue_output_cb(void* inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer)
{
	AudioQueueFreeBuffer(inAQ, inBuffer);
}

static void rdpsnd_mac_set_format(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int latency)
{
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	mac->latency = (UINT32) latency;
	CopyMemory(&(mac->format), format, sizeof(AUDIO_FORMAT));
	
	switch (format->wFormatTag)
	{
		case WAVE_FORMAT_ALAW:
			mac->audioFormat.mFormatID = kAudioFormatALaw;
			break;
			
		case WAVE_FORMAT_MULAW:
			mac->audioFormat.mFormatID = kAudioFormatULaw;
			break;
			
		case WAVE_FORMAT_PCM:
			mac->audioFormat.mFormatID = kAudioFormatLinearPCM;
			break;
			
		case WAVE_FORMAT_GSM610:
			mac->audioFormat.mFormatID = kAudioFormatMicrosoftGSM;
			break;
			
		default:
			break;
	}
	
	mac->audioFormat.mSampleRate = format->nSamplesPerSec;
	mac->audioFormat.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
	mac->audioFormat.mFramesPerPacket = 1;
	mac->audioFormat.mChannelsPerFrame = format->nChannels;
	mac->audioFormat.mBitsPerChannel = format->wBitsPerSample;
	mac->audioFormat.mBytesPerFrame = (format->wBitsPerSample * format->nChannels) / 8;
	mac->audioFormat.mBytesPerPacket = format->nBlockAlign;
	mac->audioFormat.mReserved = 0;
	
	rdpsnd_print_audio_format(format);
}

static void rdpsnd_mac_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int latency)
{
	OSStatus status;
    
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	if (mac->isOpen)
		return;
    
	mac->audioBufferIndex = 0;
    
	device->SetFormat(device, format, 0);
    
	status = AudioQueueNewOutput(&(mac->audioFormat),
				     mac_audio_queue_output_cb, mac,
				     NULL, NULL, 0, &(mac->audioQueue));
	
	if (status != 0)
	{
		fprintf(stderr, "AudioQueueNewOutput failure\n");
		return;
	}
	
	UInt32 DecodeBufferSizeFrames;
	UInt32 propertySize = sizeof(DecodeBufferSizeFrames);
	
	AudioQueueGetProperty(mac->audioQueue,
			      kAudioQueueProperty_DecodeBufferSizeFrames,
			      &DecodeBufferSizeFrames,
			      &propertySize);
	
	if (status != 0)
	{
		printf("AudioQueueGetProperty failure: kAudioQueueProperty_DecodeBufferSizeFrames\n");
	}
    
	mac->isOpen = TRUE;
}

static void rdpsnd_mac_close(rdpsndDevicePlugin* device)
{
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	if (mac->isOpen)
	{
		mac->isOpen = FALSE;
		
		AudioQueueStop(mac->audioQueue, true);
		
		AudioQueueDispose(mac->audioQueue, true);
		mac->audioQueue = NULL;
		
		mac->isPlaying = FALSE;
	}
}

static void rdpsnd_mac_free(rdpsndDevicePlugin* device)
{
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	device->Close(device);
	
	if (!DeleteTimerQueue(mac->hTimerQueue))
	{
		printf("DeleteTimerQueue failed (%d)\n", (int) GetLastError());
	}
	
	free(mac);
}

static BOOL rdpsnd_mac_format_supported(rdpsndDevicePlugin* device, AUDIO_FORMAT* format)
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

static void rdpsnd_mac_set_volume(rdpsndDevicePlugin* device, UINT32 value)
{
	OSStatus status;
	Float32 fVolume;
	UINT16 volumeLeft;
	UINT16 volumeRight;
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	if (!mac->audioQueue)
		return;
		
	volumeLeft = (value & 0xFFFF);
	volumeRight = ((value >> 16) & 0xFFFF);
	
	fVolume = ((float) volumeLeft) / 65535.0;
	
	status = AudioQueueSetParameter(mac->audioQueue, kAudioQueueParam_Volume, fVolume);
	
	if (status != 0)
	{
		fprintf(stderr, "AudioQueueSetParameter kAudioQueueParam_Volume failed: %f\n", fVolume);
	}
}

static void rdpsnd_mac_start(rdpsndDevicePlugin* device)
{
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	if (!mac->isPlaying)
	{
		OSStatus status;
		
		if (!mac->audioQueue)
			return;
		
		status = AudioQueueStart(mac->audioQueue, NULL);
		
		if (status != 0)
		{
			fprintf(stderr, "AudioQueueStart failed\n");
		}
		
		mac->isPlaying = TRUE;
	}
}

VOID CALLBACK rdpsnd_mac_timer_routine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
	UINT64 wTimeDiff;
	UINT64 mCurrentTime;
	UINT16 wTimeStampB;
	rdpsndMacPlugin* mac;
	MAC_AUDIO_APC_DATA* apcData;
	
	apcData = (MAC_AUDIO_APC_DATA*) lpParam;
	mac = apcData->mac;
	
	mCurrentTime = mach_absolute_time();
	
	wTimeDiff = mach_time_to_milliseconds(mCurrentTime - apcData->mTimeStampA);
	
	wTimeStampB = (apcData->mTimeStampA + wTimeDiff) % 0xFFFF;
	
	//fprintf(stderr, "rdpsnd_mac_timer_routine: cBlockNo: %d DueTime: %d wTimeDiff: %d\n",
	//	apcData->cBlockNo, (int) apcData->DueTime, (int) wTimeDiff);
	
	rdpsnd_send_wave_confirm_pdu(mac->device.rdpsnd, wTimeStampB, apcData->cBlockNo);
}

void rdpsnd_mac_wave_play(rdpsndDevicePlugin* device, RDPSND_WAVE* wave)
{
	int index;
	OSStatus status;
	UINT64 mEndTime;
	UINT64 mCurrentTime;
	UINT64 mAudioLength;
	MAC_AUDIO_APC_DATA* apcData;
	AudioTimeStamp inStartTime;
	AudioTimeStamp outActualStartTime;
	AudioQueueBufferRef audioBuffer;
	rdpsndMacPlugin* mac = (rdpsndMacPlugin*) device;
	
	if (!mac->isOpen)
		return;
	
	mCurrentTime = mach_absolute_time();
	
	status = AudioQueueAllocateBuffer(mac->audioQueue, wave->length, &audioBuffer);
	
	if (status != 0)
	{
		fprintf(stderr, "AudioQueueAllocateBuffer failed\n");
		return;
	}
	
	CopyMemory(audioBuffer->mAudioData, wave->data, wave->length);
	audioBuffer->mAudioDataByteSize = wave->length;
	
	ZeroMemory(&inStartTime, sizeof(AudioTimeStamp));
	
	inStartTime.mFlags = kAudioTimeStampHostTimeValid;
	inStartTime.mHostTime = mCurrentTime;
	
	status = AudioQueueEnqueueBufferWithParameters(mac->audioQueue, audioBuffer, 0, NULL,
						       0, 0, 0, NULL, &inStartTime, &outActualStartTime);
	
	if (status != 0)
	{
		printf("AudioQueueEnqueueBufferWithParameters failure\n");
		return;
	}
	
	if (!(outActualStartTime.mFlags & kAudioTimeStampHostTimeValid))
	{
		printf("AudioQueueEnqueueBufferWithParameters invalid host time\n");
		outActualStartTime.mHostTime = mCurrentTime;
	}
	
	mAudioLength = milliseconds_to_mach_time(wave->wAudioLength);
	mEndTime = outActualStartTime.mHostTime + mAudioLength;
	
	index = wave->cBlockNo;
	apcData = &(mac->apcData[index]);
	apcData->mac = mac;
	apcData->cBlockNo = wave->cBlockNo;
	apcData->mTimeStampA = mCurrentTime;
	apcData->wTimeStampA = wave->wTimeStampA;
	
	if (mEndTime < mCurrentTime)
	{
		printf("WARNING: mEndTime <= mCurrentTime: %d\n",
		       (int) mach_time_to_milliseconds(mCurrentTime - mEndTime));
		mEndTime = mCurrentTime;
	}
	
	apcData->DueTime = mach_time_to_milliseconds(mEndTime - mCurrentTime);
	
	wave->AutoConfirm = FALSE;
	wave->wTimeStampB = wave->wTimeStampA + apcData->DueTime;
	wave->wLocalTimeB = wave->wLocalTimeA + apcData->DueTime;
	
	if (!mac->hTimers[index])
	{
		if (!CreateTimerQueueTimer(&(mac->hTimers[index]), mac->hTimerQueue,
					   (WAITORTIMERCALLBACK) rdpsnd_mac_timer_routine,
					   apcData, apcData->DueTime, 0, 0))
		{
			printf("CreateTimerQueueTimer failed (%d)\n", (int) GetLastError());
		}
	}
	else
	{
		if (!ChangeTimerQueueTimer(mac->hTimerQueue, mac->hTimers[index], apcData->DueTime, 0))
		{
			printf("ChangeTimerQueueTimer failed (%d)\n", (int) GetLastError());
		}
	}
	
	device->Start(device);
}

#ifdef STATIC_CHANNELS
#define freerdp_rdpsnd_client_subsystem_entry	mac_freerdp_rdpsnd_client_subsystem_entry
#endif

int freerdp_rdpsnd_client_subsystem_entry(PFREERDP_RDPSND_DEVICE_ENTRY_POINTS pEntryPoints)
{
	rdpsndMacPlugin* mac;
    
	mac = (rdpsndMacPlugin*) malloc(sizeof(rdpsndMacPlugin));
	
	if (mac)
	{
		ZeroMemory(mac, sizeof(rdpsndMacPlugin));
	
		mac->device.Open = rdpsnd_mac_open;
		mac->device.FormatSupported = rdpsnd_mac_format_supported;
		mac->device.SetFormat = rdpsnd_mac_set_format;
		mac->device.SetVolume = rdpsnd_mac_set_volume;
		mac->device.WavePlay = rdpsnd_mac_wave_play;
		mac->device.Start = rdpsnd_mac_start;
		mac->device.Close = rdpsnd_mac_close;
		mac->device.Free = rdpsnd_mac_free;
		
		mac->device.DisableConfirmThread = TRUE;
		
		mac->hTimerQueue = CreateTimerQueue();
		
		if (!mac->hTimerQueue)
		{
			printf("CreateTimerQueue failed (%d)\n", (int) GetLastError());
			return -1;
		}
		
		mach_timebase_info(&machTimebaseInfo);
		machTimeFactorNano = (double) machTimebaseInfo.numer / machTimebaseInfo.denom;

		pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) mac);
	}

	return 0;
}
