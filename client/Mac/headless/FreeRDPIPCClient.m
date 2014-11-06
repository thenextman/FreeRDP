//
//  FreeRDPIPCClient.m
//  FreeRDP
//
//  Created by Richard Markiewicz on 2014-10-31.
//
//

#import "FreeRDPIPCClient.h"
#import "FreeRDPIPCServer.h"

@implementation FreeRDPIPCClient

static NSString* const clientBaseName = @"com.devolutions.freerdpclient";
static NSString* const MRDPClientDidPostErrorInfoNotification = @"MRDPViewDidPostErrorInfoNotification";
static NSString* const MRDPClientDidConnectWithResultNotification = @"MRDPViewDidConnectWithResultNotification";

@synthesize serverConnection;
@synthesize context;
@synthesize hostProxy;

- (void)initialiseWithServer:(NSString *)registeredName
{
    hostProxy = (id)[NSConnection rootProxyForConnectionWithRegisteredName:registeredName host:nil];
    [hostProxy setProtocolForProxy:@protocol(FreeRDPIPCServer)];
    
    if(hostProxy != nil)
    {
        NSString *serverID = [hostProxy serverID];
        NSString *clientName = [NSString stringWithFormat:@"%@.%@", clientBaseName, serverID];
        
        serverConnection = [NSConnection serviceConnectionWithName:clientName rootObject:self];
        [serverConnection runInNewThread];
        [serverConnection registerName:clientName];
        
        [hostProxy clientConnected:clientName];
    }
}

- (void)viewDidConnect:(NSNotification *)notification
{
    rdpContext *ctx;
    
    [[[notification userInfo] valueForKey:@"context"] getValue:&ctx];
    
    if(ctx == self->context)
    {
        NSLog(@"viewDidConnect:");
        
        ConnectionResultEventArgs *e = nil;
        [[[notification userInfo] valueForKey:@"connectionArgs"] getValue:&e];
        
        if(e->result == 0)
        {
            mfContext* mfc = (mfContext*)context;
            MRDPClient* view = (MRDPClient*) mfc->view;
            view.delegate = self;
            
            [hostProxy rdpConnected:view.framebufferId];
//            if(delegate && [delegate respondsToSelector:@selector(didConnect)])
//            {
//                // Better to replace this (and others in this class) with dispatch_async(dispatch_get_main_queue(), ^{ ... }) ?
//                // It doesn't care about run loop modes...
//                [delegate performSelectorOnMainThread:@selector(didConnect) withObject:nil waitUntilDone:true];
//            }
        }
        else
        {
//            if(delegate && [delegate respondsToSelector:@selector(didFailToConnectWithError:)])
//            {
//                NSNumber *connectErrorCode =  [NSNumber numberWithUnsignedInt:freerdp_get_last_error(ctx)];
//                
//                [delegate performSelectorOnMainThread:@selector(didFailToConnectWithError:) withObject:connectErrorCode waitUntilDone:true];
//            }
        }
    }
}

- (void)configure
{
    mfContext* mfc;
    
    if(self.context == nil)
    {
        [self createContext];
    }
    
    rdpSettings *settings = context->settings;
    settings->SoftwareGdi = TRUE;
    
    mfc = (mfContext*)context;
    mfc->view = (void*)mrdpClient;
    
    PubSub_SubscribeConnectionResult(context->pubSub, ConnectionResultEventHandler);
    PubSub_SubscribeErrorInfo(context->pubSub, ErrorInfoEventHandler);
}

- (void)start
{
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(viewDidConnect:) name:MRDPClientDidConnectWithResultNotification object:nil];
    
    freerdp_client_start(context);
}

- (void)stop
{
    PubSub_UnsubscribeConnectionResult(context->pubSub, ConnectionResultEventHandler);
    PubSub_UnsubscribeErrorInfo(context->pubSub, ErrorInfoEventHandler);
    
    freerdp_client_stop(context);
    
    freerdp_client_context_free(context);
}

- (void)restart
{
    
}

- (void)mouseMoved:(NSEvent *)event
{
    printf("moving mouse!");
    
    mfContext* mfc = (mfContext*)context;
    MRDPClient* view = (MRDPClient*) mfc->view;
    
    [view mouseMoved:event];
}

- (void)createContext
{
    RDP_CLIENT_ENTRY_POINTS clientEntryPoints;
    
    ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
    clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
    clientEntryPoints.Version = RDP_CLIENT_INTERFACE_VERSION;
    
    RdpClientEntry(&clientEntryPoints);
    
    context = freerdp_client_context_new(&clientEntryPoints);
}

- (void)releaseContext
{
    freerdp_client_context_free(context);
    context = nil;
}

- (BOOL)getBooleanSettingForIdentifier:(int)identifier
{
    return freerdp_get_param_bool(context->settings, identifier);
}

- (int)setBooleanSettingForIdentifier:(int)identifier withValue:(BOOL)value
{
    return freerdp_set_param_bool(context->settings, identifier, value);
}

- (int)getIntegerSettingForIdentifier:(int)identifier
{
    return freerdp_get_param_int(context-> settings, identifier);
}

- (int)setIntegerSettingForIdentifier:(int)identifier withValue:(int)value
{
    return freerdp_set_param_int(context->settings, identifier, value);
}

- (uint32)getInt32SettingForIdentifier:(int)identifier
{
    return freerdp_get_param_uint32(context-> settings, identifier);
}

- (int)setInt32SettingForIdentifier:(int)identifier withValue:(uint32)value
{
    return freerdp_set_param_uint32(context->settings, identifier, value);
}

- (uint64)getInt64SettingForIdentifier:(int)identifier
{
    return freerdp_get_param_uint64(context-> settings, identifier);
}

- (int)setInt64SettingForIdentifier:(int)identifier withValue:(uint64)value
{
    return freerdp_set_param_uint64(context->settings, identifier, value);
}

- (NSString *)getStringSettingForIdentifier:(int)identifier
{
    char* cString = freerdp_get_param_string(context-> settings, identifier);
    
    return cString ? [NSString stringWithUTF8String:cString] : nil;
}

- (int)setStringSettingForIdentifier:(int)identifier withValue:(NSString *)value
{
    char* cString = (char*)[value UTF8String];
    
    return freerdp_set_param_string(context->settings, identifier, cString);
}

- (double)getDoubleSettingForIdentifier:(int)identifier
{
    return freerdp_get_param_double(context-> settings, identifier);
}

- (int)setDoubleSettingForIdentifier:(int)identifier withValue:(double)value
{
    return freerdp_set_param_double(context->settings, identifier, value);
}

- (void)setNeedsDisplayInRect:(NSRect)newDrawRect
{
    [hostProxy drawDirtyRect:newDrawRect.origin.x Y:newDrawRect.origin.y HEIGHT:newDrawRect.size.height WIDTH:newDrawRect.size.width];
}

/**
 * Client Interface
 */

void mfreerdp_client_global_init()
{
    freerdp_handle_signals();
}

void mfreerdp_client_global_uninit()
{
    
}

int mfreerdp_client_start(rdpContext* context)
{
    MRDPClient* view;
    mfContext* mfc = (mfContext*) context;
    
    if (mfc->view == NULL)
    {
        // view not specified beforehand. Create view dynamically
        mfc->view = [[MRDPClient alloc] init];
//        mfc->view = [[MRDPView alloc] initWithFrame : NSMakeRect(0, 0, context->settings->DesktopWidth, context->settings->DesktopHeight)];
//        mfc->view_ownership = TRUE;
    }
    
    view = (MRDPClient*) mfc->view;
    [view rdpStart:context];
    
    return 0;
}

int mfreerdp_client_stop(rdpContext* context)
{
    mfContext* mfc = (mfContext*) context;
    
    if (mfc->thread)
    {
        SetEvent(mfc->stopEvent);
        WaitForSingleObject(mfc->thread, INFINITE);
        CloseHandle(mfc->thread);
        mfc->thread = NULL;
    }
    
    if (mfc->view_ownership)
    {
        MRDPClient* view = (MRDPClient*) mfc->view;
        [view releaseResources];
        [view release];
        mfc->view = nil;
    }
    
    return 0;
}

int mfreerdp_client_new(freerdp* instance, rdpContext* context)
{
    mfContext* mfc;
    rdpSettings* settings;
    
    mfc = (mfContext*) instance->context;
    
    mfc->stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    context->instance->PreConnect = mac_pre_connect;
    context->instance->PostConnect = mac_post_connect;
    context->instance->Authenticate = mac_authenticate;
    
    context->channels = freerdp_channels_new();
    
    settings = instance->settings;
    
    settings->AsyncTransport = TRUE;
    
    settings->AsyncUpdate = TRUE;
    settings->AsyncInput = TRUE;
    settings->AsyncChannels = TRUE;
    
    return 0;
}

void mfreerdp_client_free(freerdp* instance, rdpContext* context)
{
    
}

void freerdp_client_mouse_event(rdpContext* cfc, DWORD flags, int x, int y)
{
    int width, height;
    rdpInput* input = cfc->instance->input;
    rdpSettings* settings = cfc->instance->settings;
    
    width = settings->DesktopWidth;
    height = settings->DesktopHeight;
    
    if (x < 0)
        x = 0;
    
    x = width - 1;
    
    if (y < 0)
        y = 0;
    
    if (y >= height)
        y = height - 1;
    
    input->MouseEvent(input, flags, x, y);
}

void mf_scale_mouse_event(void* context, rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
    mfContext* mfc = (mfContext*) context;
    MRDPClient* view = (MRDPClient*) mfc->view;
    
    int ww, wh, dw, dh;
    
    ww = mfc->client_width;
    wh = mfc->client_height;
    dw = mfc->context.settings->DesktopWidth;
    dh = mfc->context.settings->DesktopHeight;
    
    // Convert to windows coordinates
    //y = [view frame].size.height - y;
    y = 480 - y;
    
    if (!mfc->context.settings->SmartSizing || ((ww == dw) && (wh == dh)))
    {
        y = y + mfc->yCurrentScroll;
        
        if (wh != dh)
        {
            y -= (dh - wh);
        }
        
        input->MouseEvent(input, flags, x + mfc->xCurrentScroll, y);
    }
    else
    {
        y = y * dh / wh + mfc->yCurrentScroll;
        input->MouseEvent(input, flags, x * dw / ww + mfc->xCurrentScroll, y);
    }
}

int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints)
{
    pEntryPoints->Version = 1;
    pEntryPoints->Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
    
    pEntryPoints->GlobalInit = mfreerdp_client_global_init;
    pEntryPoints->GlobalUninit = mfreerdp_client_global_uninit;
    
    pEntryPoints->ContextSize = sizeof(mfContext);
    pEntryPoints->ClientNew = mfreerdp_client_new;
    pEntryPoints->ClientFree = mfreerdp_client_free;
    
    pEntryPoints->ClientStart = mfreerdp_client_start;
    pEntryPoints->ClientStop = mfreerdp_client_stop;
    
    return 0;
}

void ConnectionResultEventHandler(void* ctx, ConnectionResultEventArgs* e)
{
    @autoreleasepool
    {
        NSLog(@"ConnectionResultEventHandler");
        
        rdpContext* context = (rdpContext*) ctx;

        NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:[NSValue valueWithPointer:context], @"context",
                                  [NSValue valueWithPointer:e], @"connectionArgs",
                                  [NSNumber numberWithInt:connectErrorCode], @"connectErrorCode", nil];
        
        [[NSNotificationCenter defaultCenter] postNotificationName:MRDPClientDidConnectWithResultNotification object:nil userInfo:userInfo];
    }
}

void ErrorInfoEventHandler(void* ctx, ErrorInfoEventArgs* e)
{
    @autoreleasepool
    {
        NSLog(@"ErrorInfoEventHandler");
        
        rdpContext* context = (rdpContext*) ctx;
        
        NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:[NSValue valueWithPointer:context], @"context",
                                  [NSValue valueWithPointer:e], @"errorArgs", nil];
        
        [[NSNotificationCenter defaultCenter] postNotificationName:MRDPClientDidPostErrorInfoNotification object:nil userInfo:userInfo];
    }
}

@end
