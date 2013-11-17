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
	AudioComponentInstance audioUnit;
	CRITICAL_SECTION lock;
	
	BOOL isOpen;
	BOOL isPlaying;
	int bytesPerFrame;
	
	AUDIO_FORMAT format;
	wQueue* RenderQueue;
	wQueue* PendingQueue;
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
	
	if (*ioActionFlags == kAudioUnitRenderAction_PostRender)
	{
		int inNumberBytes;
		RDPSND_WAVE* wave;
		AudioBuffer* audioBuffer = &ioData->mBuffers[0];
		
		inNumberBytes = inNumberFrames * p->bytesPerFrame;
		inNumberBytes /= (p->format.nChannels / audioBuffer->mNumberChannels);
		
		printf("AudioUnitRenderNotifyCallback: inNumberFrames: %d inNumberBytes: %d mBuffer[%d]: mDataByteSize: %d mNumberChannels: %d format->nChannels: %d\n",
		       (unsigned int) inNumberFrames, inNumberBytes, 0,
		       (unsigned int) audioBuffer->mDataByteSize,
		       (unsigned int) audioBuffer->mNumberChannels,
		       p->format.nChannels);
		
		wave = Queue_Peek(p->RenderQueue);
		
		if (!wave)
		{
			printf("empty wave queue!\n");
			return noErr;
		}
		
		wave->offset += inNumberBytes;
		
		if (wave->offset >= wave->length)
		{
			UINT16 diff;
			UINT16 wCurrentTime;
			
			wave = Queue_Dequeue(p->RenderQueue);
			
			wCurrentTime = (UINT16) GetTickCount();
			diff = wCurrentTime - wave->wLocalTimeA;
			wave->wTimeStampB = wave->wTimeStampA + diff;
			
			rdpsnd_send_wave_confirm_pdu(p->device.rdpsnd, wave->wTimeStampB, wave->cBlockNo);
			
			printf("\tConfirm %02X wTimeStampA: %d wTimeStampB: %d diff: %d\n",
			       wave->cBlockNo, wave->wTimeStampA, wave->wTimeStampB, diff);
			
			free(wave->data);
			free(wave);
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
			
			printf("AudioUnitRenderCallback: inNumberFrames: %d inNumberBytes: %d mBuffer[%d]: mDataByteSize: %d mNumberChannels: %d format->nChannels: %d\n",
			       (unsigned int) inNumberFrames, copyLength, 0,
			       (unsigned int) audioBuffer->mDataByteSize,
			       (unsigned int) audioBuffer->mNumberChannels,
			       p->format.nChannels);
			
			CopyMemory(audioBuffer->mData, &(wave->data[wave->offset]), copyLength);
			audioBuffer->mDataByteSize = copyLength;
			wave->offset += copyLength;
			
			if (wave->offset >= wave->length)
			{
				wave = Queue_Dequeue(p->PendingQueue);
				wave->offset = 0;
				
				Queue_Enqueue(p->RenderQueue, wave);
			}
		}
		else
		{
			*ioActionFlags |= kAudioUnitRenderAction_OutputIsSilence;
			
			audioBuffer->mDataByteSize = 0;
			AudioOutputUnitStop(p->audioUnit);
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
	}
}

static void rdpsnd_ios_stop(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;

	if (p->isPlaying)
	{
		/* Stop the device. */
		AudioOutputUnitStop(p->audioUnit);
		p->isPlaying = FALSE;
		
		Queue_Free(p->PendingQueue);
		Queue_Free(p->RenderQueue);
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
	
	wave->data = (BYTE*) malloc(length);
	CopyMemory(wave->data, data, length);
	
	Queue_Enqueue(p->PendingQueue, wave);
	
	printf("Enqueue: wave [cBlockNo: %02X wLocalTimeA: %d wTimeStampA: %d frames: %d]\n",
	       wave->cBlockNo,
	       wave->wLocalTimeA,
	       wave->wTimeStampA,
	       (length / p->bytesPerFrame));
	
	rdpsnd_ios_start(device);
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int __unused latency)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	if (p->isOpen)
		return;
	
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
	OSStatus status = AudioComponentInstanceNew(audioComponent, &p->audioUnit);
	
	if (status != 0)
		return;
	
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
	
	status = AudioUnitSetProperty(
				      p->audioUnit,
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
	status = AudioUnitSetProperty(
				      p->audioUnit,
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
	
	/* Initialize the AudioUnit. */
	status = AudioUnitInitialize(p->audioUnit);
	
	if (status != 0)
	{
		printf("Failed to init the Audio Unit\n");
		AudioComponentInstanceDispose(p->audioUnit);
		p->audioUnit = NULL;
		return;
	}
	
	p->isOpen = TRUE;
	
	InitializeCriticalSectionAndSpinCount(&(p->lock), 4000);
	
	p->RenderQueue = Queue_New(TRUE, 0, 0);
	p->PendingQueue = Queue_New(TRUE, 0, 0);
	
	Float64 lat64;
	UInt32 data_size;
	
	status = AudioUnitGetProperty(p->audioUnit,
				      kAudioUnitProperty_Latency,
				      kAudioUnitScope_Global,
				      0,
				      &lat64,
				      &data_size);
	
	printf("audio unit latency: %.06fms\n", lat64 * 1000.0);
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
	ZeroMemory(p, sizeof(rdpsndIOSPlugin));
	
	p->device.Open = rdpsnd_ios_open;
	p->device.FormatSupported = rdpsnd_ios_format_supported;
	p->device.SetFormat = rdpsnd_ios_set_format;
	p->device.SetVolume = rdpsnd_ios_set_volume;
	//p->device.Play = rdpsnd_ios_play;
	p->device.Start = rdpsnd_ios_start;
	p->device.Close = rdpsnd_ios_close;
	p->device.Free = rdpsnd_ios_free;
	p->device.WavePlay = rdpsnd_ios_wave_play;
	
	pEntryPoints->pRegisterRdpsndDevice(pEntryPoints->rdpsnd, (rdpsndDevicePlugin*) p);
	
	return 0;
}