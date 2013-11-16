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
#include "TPCircularBuffer.h"

#define INPUT_BUFFER_SIZE       1048576
#define CIRCULAR_BUFFER_SIZE    (INPUT_BUFFER_SIZE * 4)

struct rdpsnd_ios_plugin
{
	rdpsndDevicePlugin device;
	AudioComponentInstance audio_unit;
	TPCircularBuffer buffer;
	CRITICAL_SECTION lock;
	BOOL is_opened;
	BOOL is_playing;
	
	int bpsAvg;
	int bytesPerFrame;
	int frameCnt;
	wQueue* waveQ;
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
		int targetFrames;
		RDPSND_WAVE* wave;
		AudioBuffer* audioBuffer = &ioData->mBuffers[0];
		
		printf("AudioUnitRenderNotifyCallback: inNumberFrames: %d mBuffer[%d]: mDataByteSize: %d mNumberChannels: %d\n",
		       (unsigned int) inNumberFrames, 0,
		       (unsigned int) audioBuffer->mDataByteSize, (unsigned int) audioBuffer->mNumberChannels);
		
		wave = Queue_Peek(p->waveQ);
		
		if (!wave)
		{
			printf("empty wave queue!\n");
			return noErr;
		}
		
		targetFrames = wave->length / p->bytesPerFrame;
		
		if (p->frameCnt >= targetFrames)
		{
			UINT16 diff;
			UINT16 wCurrentTime;
			
			wCurrentTime = (UINT16) GetTickCount();
			diff = wCurrentTime - wave->wLocalTimeA;
			
			p->frameCnt = 0;
			
			wave = Queue_Dequeue(p->waveQ);
			
			rdpsnd_send_wave_confirm_pdu(p->device.rdpsnd, wave->wTimeStampA + diff, wave->cBlockNo);
			
			printf("\tConfirm %02X timeStamp A:%d B:%d diff %d (qCount=%d)\n",
			       wave->cBlockNo,
			       wave->wTimeStampA,
			       wave->wTimeStampA + diff,
			       diff,
			       Queue_Count(p->waveQ));
			
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
	
	if (inBusNumber != 0)
	{
		return noErr;
	}
	
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) inRefCon;
	
	for (i = 0; i < ioData->mNumberBuffers; i++)
	{
		AudioBuffer* audioBuffer = &ioData->mBuffers[i];
		
		printf("AudioUnitRenderCallback: inNumberFrames: %d mBuffer[%d]: mDataByteSize: %d mNumberChannels: %d\n",
		       (unsigned int) inNumberFrames, 0,
		       (unsigned int) audioBuffer->mDataByteSize, (unsigned int) audioBuffer->mNumberChannels);
		
		int32_t available_bytes = 0;
		const void* buffer = TPCircularBufferTail(&p->buffer, &available_bytes);
		
		if ((buffer != NULL) && (available_bytes > 0))
		{
			const int bytes_to_copy = MIN((int32_t) audioBuffer->mDataByteSize, available_bytes);
			
			CopyMemory(audioBuffer->mData, buffer, bytes_to_copy);
			audioBuffer->mDataByteSize = bytes_to_copy;
			
			TPCircularBufferConsume(&p->buffer, bytes_to_copy);
			
			p->frameCnt += inNumberFrames;
		}
		else
		{
			*ioActionFlags = *ioActionFlags | kAudioUnitRenderAction_OutputIsSilence;
			
			audioBuffer->mDataByteSize = 0;
			AudioOutputUnitStop(p->audio_unit);
			p->is_playing = FALSE;
			
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

static void rdpsnd_ios_set_format(rdpsndDevicePlugin* __unused device, AUDIO_FORMAT* __unused format, int __unused latency)
{
	
}

static void rdpsnd_ios_set_volume(rdpsndDevicePlugin* __unused device, UINT32 __unused value)
{
	
}

static void rdpsnd_ios_start(rdpsndDevicePlugin* device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;

	if (!p->is_playing)
	{
		/* Start the device. */
		int32_t available_bytes = 0;
		TPCircularBufferTail(&p->buffer, &available_bytes);
		
		if (available_bytes > 0)
		{
			p->is_playing = TRUE;
			AudioOutputUnitStart(p->audio_unit);
		}
		else
		{
			printf("[!!!] start: available bytes = %d\n", available_bytes);
		}
	}
	else
	{
		//printf("[!!!] Start called while playing!\n");
	}
}

static void rdpsnd_ios_stop(rdpsndDevicePlugin* __unused device)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;

	if (p->is_playing)
	{
		/* Stop the device. */
		AudioOutputUnitStop(p->audio_unit);
		p->is_playing = FALSE;
		
		/* Free all buffers. */
		TPCircularBufferClear(&p->buffer);
	}
}

static void rdpsnd_ios_wave_play(rdpsndDevicePlugin* device, RDPSND_WAVE* wave)
{
	BYTE* data;
	int length;
	
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	data = wave->data;
	length = wave->length;
	wave->AutoConfirm = FALSE;
	
	const BOOL ok = TPCircularBufferProduceBytes(&p->buffer, data, length);

	if (!ok)
	{
		printf("[!!!] Failed to produce bytes from buffer!\n");
		return;
	}
	
	Queue_Enqueue(p->waveQ, wave);
	
	printf("Enqueue: wave [cBlockNo:%02X localA:%d remoteA:%d frames:%d] count = %d\n",
	       wave->cBlockNo,
	       wave->wLocalTimeA,
	       wave->wTimeStampA,
	       (length / p->bytesPerFrame),
	       Queue_Count(p->waveQ));
	
	rdpsnd_ios_start(device);
}

static void rdpsnd_ios_open(rdpsndDevicePlugin* device, AUDIO_FORMAT* format, int __unused latency)
{
	rdpsndIOSPlugin* p = (rdpsndIOSPlugin*) device;
	
	if (p->is_opened)
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
	OSStatus status = AudioComponentInstanceNew(audioComponent, &p->audio_unit);
	
	if (status != 0)
		return;
	
	/* Set the format for the AudioUnit. */
	/*
	 AudioStreamBasicDescription audioFormat = {0};
	 audioFormat.mSampleRate       = format->nSamplesPerSec;
	 audioFormat.mFormatID         = kAudioFormatLinearPCM;
	 audioFormat.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
	 audioFormat.mFramesPerPacket  = 1; // imminent property of the Linear PCM
	 audioFormat.mChannelsPerFrame = format->nChannels;
	 audioFormat.mBitsPerChannel   = format->wBitsPerSample;
	 audioFormat.mBytesPerFrame    = (format->wBitsPerSample * format->nChannels) / 8;
	 audioFormat.mBytesPerPacket   = audioFormat.mBytesPerFrame * audioFormat.mFramesPerPacket;
	 
	 bytesPerFrame = audioFormat.mBytesPerFrame;
	 */
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
	p->bpsAvg = format->nAvgBytesPerSec;
	
	rdpsnd_print_audio_format(format);
	
	status = AudioUnitSetProperty(
				      p->audio_unit,
				      kAudioUnitProperty_StreamFormat,
				      kAudioUnitScope_Input,
				      0,
				      &audioFormat,
				      sizeof(audioFormat));
	
	if (status != 0)
	{
		printf("Failed to set audio unit property\n");
		AudioComponentInstanceDispose(p->audio_unit);
		p->audio_unit = NULL;
		return;
	}
	
	/* Register Audio Unit Render Callback */
	
	AURenderCallbackStruct callbackStruct = { 0 };
	callbackStruct.inputProc = rdpsnd_ios_render_cb;
	callbackStruct.inputProcRefCon = p;
	status = AudioUnitSetProperty(
				      p->audio_unit,
				      kAudioUnitProperty_SetRenderCallback,
				      kAudioUnitScope_Input,
				      0,
				      &callbackStruct,
				      sizeof(callbackStruct));
	
	if (status != 0)
	{
		printf("Failed to set audio unit callback\n");
		AudioComponentInstanceDispose(p->audio_unit);
		p->audio_unit = NULL;
		return;
	}
	
	/* Render Notify Callback */
	status = AudioUnitAddRenderNotify(p->audio_unit, rdpsnd_ios_render_notify_cb, p);
	
	if (status != 0)
	{
		printf("Could not register render notify callback!\n");
		AudioComponentInstanceDispose(p->audio_unit);
		p->audio_unit = NULL;
		return;
	}
	
	/* Initialize the AudioUnit. */
	status = AudioUnitInitialize(p->audio_unit);
	
	if (status != 0)
	{
		printf("Failed to init the Audio Unit\n");
		AudioComponentInstanceDispose(p->audio_unit);
		p->audio_unit = NULL;
		return;
	}
	
	/* Allocate the circular buffer. */
	const BOOL ok = TPCircularBufferInit(&p->buffer, CIRCULAR_BUFFER_SIZE);
	
	if (!ok)
	{
		printf("Failed to init the TPCircularBuffer\n");
		AudioUnitUninitialize(p->audio_unit);
		AudioComponentInstanceDispose(p->audio_unit);
		p->audio_unit = NULL;
		return;
	}
	
	p->is_opened = TRUE;
	
	InitializeCriticalSectionAndSpinCount(&(p->lock), 4000);
	
	p->frameCnt = 0;
	p->waveQ = Queue_New(TRUE, 32, 2);
	
	Float64 lat64;
	UInt32 data_size;
	
	status = AudioUnitGetProperty(p->audio_unit,
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
	
	if (p->is_opened)
	{
		/* Close the device. */
		AudioUnitUninitialize(p->audio_unit);
		AudioComponentInstanceDispose(p->audio_unit);
		p->audio_unit = NULL;
		p->is_opened = 0;
		
		/* Destroy the circular buffer. */
		TPCircularBufferCleanup(&p->buffer);
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