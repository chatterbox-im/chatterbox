// SystemConfigurationStubs.c
//
// hickory-resolver (the DNS crate used by tokio-xmpp) links against
// SystemConfiguration.framework APIs that are macOS-only and absent from the
// iOS SDK.  These stub implementations satisfy the linker.  They return
// NULL/false so hickory-resolver falls back to its built-in default DNS
// servers (8.8.8.8 / 8.8.4.4) instead of reading system DNS config.
//
// The iOS-available Reachability symbols (SCNetworkReachability*) are
// provided by the real SystemConfiguration.framework linked via
// OTHER_LDFLAGS = -framework SystemConfiguration.

#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>

// SCDynamicStore (not on iOS)
CFDictionaryRef SCDynamicStoreCopyProxies(void *store) { return NULL; }
CFPropertyListRef SCDynamicStoreCopyValue(void *store, CFStringRef key) { return NULL; }
void *SCDynamicStoreCreateRunLoopSource(CFAllocatorRef alloc, void *store, CFIndex order) { return NULL; }
void *SCDynamicStoreCreateWithOptions(CFAllocatorRef alloc, CFStringRef name, CFDictionaryRef options, void *callback, void *context) { return NULL; }

// SCNetworkInterface (not on iOS)
CFArrayRef  SCNetworkInterfaceCopyAll(void) { return NULL; }
CFStringRef SCNetworkInterfaceGetBSDName(void *iface) { return NULL; }
CFStringRef SCNetworkInterfaceGetInterfaceType(void *iface) { return NULL; }
CFStringRef SCNetworkInterfaceGetLocalizedDisplayName(void *iface) { return NULL; }

// SCNetworkService (not on iOS)
CFArrayRef  SCNetworkServiceCopyAll(void *prefs) { return NULL; }
bool        SCNetworkServiceGetEnabled(void *service) { return false; }
void       *SCNetworkServiceGetInterface(void *service) { return NULL; }
CFStringRef SCNetworkServiceGetServiceID(void *service) { return NULL; }

// SCNetworkSet (not on iOS)
void       *SCNetworkSetCopyCurrent(void *prefs) { return NULL; }
CFArrayRef  SCNetworkSetGetServiceOrder(void *set) { return NULL; }

// SCPreferences (not on iOS)
void *SCPreferencesCreate(CFAllocatorRef alloc, CFStringRef name, CFStringRef prefsID) { return NULL; }

// String constants — returning NULL is safe because they're only compared
// against interface type strings returned by SCNetworkInterfaceGetInterfaceType,
// which itself returns NULL above (so comparisons never occur).
const void *kSCDynamicStoreUseSessionKeys    = NULL;
const void *kSCNetworkInterfaceType6to4      = NULL;
const void *kSCNetworkInterfaceTypeBluetooth = NULL;
const void *kSCNetworkInterfaceTypeBond      = NULL;
const void *kSCNetworkInterfaceTypeEthernet  = NULL;
const void *kSCNetworkInterfaceTypeFireWire  = NULL;
const void *kSCNetworkInterfaceTypeIEEE80211 = NULL;
const void *kSCNetworkInterfaceTypeIPSec     = NULL;
const void *kSCNetworkInterfaceTypeIPv4      = NULL;
const void *kSCNetworkInterfaceTypeL2TP      = NULL;
const void *kSCNetworkInterfaceTypeModem     = NULL;
const void *kSCNetworkInterfaceTypePPP       = NULL;
const void *kSCNetworkInterfaceTypePPTP      = NULL;
const void *kSCNetworkInterfaceTypeSerial    = NULL;
const void *kSCNetworkInterfaceTypeVLAN      = NULL;
const void *kSCNetworkInterfaceTypeWWAN      = NULL;
