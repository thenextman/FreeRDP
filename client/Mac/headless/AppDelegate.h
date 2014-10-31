//
//  AppDelegate.h
//  MacClient2
//
//  Created by Benoît et Kathy on 2013-05-08.
//
//

#import <Cocoa/Cocoa.h>
#import <MacFreeRDP/MRDPView.h>
#import <MacFreeRDP/mfreerdp.h>

#import "FreeRDPIPCClient.h"

@interface AppDelegate : NSObject <NSApplicationDelegate>
{
    FreeRDPIPCClient *ipcClient;
    
    @public
        rdpContext* context;
        MRDPView* mrdpView;
}

- (void) rdpConnectError: (NSString*) customMessage;

@property (nonatomic, retain) FreeRDPIPCClient *ipcClient;
@property (assign) rdpContext *context;

@end
