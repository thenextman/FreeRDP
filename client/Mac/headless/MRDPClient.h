//
//  MRDPClient.h
//  FreeRDP
//
//  Created by Richard Markiewicz on 2014-10-27.
//
//

#import <Foundation/Foundation.h>

#import <Cocoa/Cocoa.h>

#import "MacFreeRDP/mfreerdp.h"
#import "MacFreeRDP/mf_client.h"
#import "MacFreeRDP/Keyboard.h"

@interface MRDPClient : NSObject
{
    mfContext* mfc;
    NSBitmapImageRep* bmiRep;
    NSMutableArray* cursors;
    NSMutableArray* windows;
    NSTimer* pasteboard_timer;
    NSCursor* currentCursor;
    NSRect prevWinPosition;
    freerdp* instance;
    rdpContext* context;
    CGContextRef bitmap_context;
    char* pixel_data;
    int argc;
    char** argv;
    DWORD kbdModFlags;
    BOOL initialized;
    NSPoint savedDragLocation;
    BOOL firstCreateWindow;
    BOOL isMoveSizeInProgress;
    BOOL skipResizeOnce;
    BOOL saveInitialDragLoc;
    BOOL skipMoveWindowOnce;

    @public
    NSPasteboard* pasteboard_rd; /* for reading from clipboard */
    NSPasteboard* pasteboard_wr; /* for writing to clipboard */
    int pasteboard_changecount;
    int pasteboard_format;
    int is_connected;
}

- (int)  rdpStart :(rdpContext*) rdp_context;
- (void) setCursor: (NSCursor*) cursor;
- (void) setScrollOffset:(int)xOffset y:(int)yOffset w:(int)width h:(int)height;

- (void) onPasteboardTimerFired :(NSTimer *) timer;
- (void) releaseResources;

@property (assign) int is_connected;

@end

/* Pointer Flags */
#define PTR_FLAGS_WHEEL                 0x0200
#define PTR_FLAGS_WHEEL_NEGATIVE        0x0100
#define PTR_FLAGS_MOVE                  0x0800
#define PTR_FLAGS_DOWN                  0x8000
#define PTR_FLAGS_BUTTON1               0x1000
#define PTR_FLAGS_BUTTON2               0x2000
#define PTR_FLAGS_BUTTON3               0x4000
#define WheelRotationMask               0x01FF

BOOL mac_pre_connect(freerdp* instance);
BOOL mac_post_connect(freerdp*	instance);
BOOL mac_authenticate(freerdp* instance, char** username, char** password, char** domain);

DWORD mac_client_thread(void* param);
