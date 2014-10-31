//
//  main.m
//

#import <Foundation/Foundation.h>

#import "AppDelegate.h"
#import "MacFreeRDP/mfreerdp.h"
#import "MRDPClient.h"

int main(int argc, const char * argv[])
{
//    @autoreleasepool {
//        NSArray *args = [[NSProcessInfo processInfo] arguments];
//        printf("Arguments\n");
//        for(int i = 0; i < [args count]; i++)
//        {
//            printf("%s\n", [args[i] UTF8String]);
//        }
//    }
//    return 0;
    
    
    AppDelegate * delegate = [[AppDelegate alloc] init];
    
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
    
    NSApplication * application = [NSApplication sharedApplication];
    [application setDelegate:delegate];
    [NSApp run];
    
    [pool drain];
    
    [delegate release];
    
    /*
    @autoreleasepool
    {
        int index;
        int status;
        HANDLE thread;
        mfContext* mfc;
        DWORD dwExitCode;
        rdpContext* context;
        rdpSettings* settings;
        RDP_CLIENT_ENTRY_POINTS clientEntryPoints;
        
        ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
        clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
        clientEntryPoints.Version = RDP_CLIENT_INTERFACE_VERSION;
        
        RdpClientEntry(&clientEntryPoints);
        
        context = freerdp_client_context_new(&clientEntryPoints);
        
        settings = context->settings;
        mfc = (mfContext*) context;
        
        settings->SoftwareGdi = TRUE;
        
        NSArray* args = [[NSProcessInfo processInfo] arguments];
        
        context->argc = (int) [args count];
        context->argv = malloc(sizeof(char*) * context->argc);
        
        for (index = 0; index < context->argc; index++)
            context->argv[index] = _strdup([args[index] UTF8String]);
        
        status = freerdp_client_settings_parse_command_line(settings, context->argc, context->argv);
        
        status = freerdp_client_settings_command_line_status_print(settings, status, context->argc, context->argv);
        
        if (status)
        {
            freerdp_client_context_free(context);
            return 0;
        }
        
        freerdp_client_start(context);
        
        thread = freerdp_client_get_thread(context);
        
        WaitForSingleObject(thread, INFINITE);
        
        GetExitCodeThread(thread, &dwExitCode);
        
        freerdp_client_stop(context);
        
        freerdp_client_context_free(context);
    }
    return 0;
    */
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
    MRDPView* view;
    mfContext* mfc = (mfContext*) context;
    
    if (mfc->view == NULL)
    {
        // view not specified beforehand. Create view dynamically
        mfc->view = [[MRDPView alloc] initWithFrame : NSMakeRect(0, 0, context->settings->DesktopWidth, context->settings->DesktopHeight)];
        mfc->view_ownership = TRUE;
    }
    
    view = (MRDPView*) mfc->view;
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
    y = [view frame].size.height - y;
    
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