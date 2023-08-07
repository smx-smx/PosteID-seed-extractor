from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CheckinRequest(_message.Message):
    __slots__ = ["imei", "androidId", "digest", "checkin", "desiredBuild", "locale", "loggingId", "marketCheckin", "macAddress", "meid", "accountCookie", "timeZone", "securityToken", "version", "otaCert", "serial", "esn", "deviceConfiguration", "macAddressType", "fragment", "userName", "userSerialNumber"]
    class Checkin(_message.Message):
        __slots__ = ["build", "lastCheckinMs", "event", "stat", "requestedGroup", "cellOperator", "simOperator", "roaming", "userNumber"]
        class Build(_message.Message):
            __slots__ = ["fingerprint", "hardware", "brand", "radio", "bootloader", "clientId", "time", "packageVersionCode", "device", "sdkVersion", "model", "manufacturer", "product", "otaInstalled"]
            FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
            HARDWARE_FIELD_NUMBER: _ClassVar[int]
            BRAND_FIELD_NUMBER: _ClassVar[int]
            RADIO_FIELD_NUMBER: _ClassVar[int]
            BOOTLOADER_FIELD_NUMBER: _ClassVar[int]
            CLIENTID_FIELD_NUMBER: _ClassVar[int]
            TIME_FIELD_NUMBER: _ClassVar[int]
            PACKAGEVERSIONCODE_FIELD_NUMBER: _ClassVar[int]
            DEVICE_FIELD_NUMBER: _ClassVar[int]
            SDKVERSION_FIELD_NUMBER: _ClassVar[int]
            MODEL_FIELD_NUMBER: _ClassVar[int]
            MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
            PRODUCT_FIELD_NUMBER: _ClassVar[int]
            OTAINSTALLED_FIELD_NUMBER: _ClassVar[int]
            fingerprint: str
            hardware: str
            brand: str
            radio: str
            bootloader: str
            clientId: str
            time: int
            packageVersionCode: int
            device: str
            sdkVersion: int
            model: str
            manufacturer: str
            product: str
            otaInstalled: bool
            def __init__(self, fingerprint: _Optional[str] = ..., hardware: _Optional[str] = ..., brand: _Optional[str] = ..., radio: _Optional[str] = ..., bootloader: _Optional[str] = ..., clientId: _Optional[str] = ..., time: _Optional[int] = ..., packageVersionCode: _Optional[int] = ..., device: _Optional[str] = ..., sdkVersion: _Optional[int] = ..., model: _Optional[str] = ..., manufacturer: _Optional[str] = ..., product: _Optional[str] = ..., otaInstalled: bool = ...) -> None: ...
        class Event(_message.Message):
            __slots__ = ["tag", "value", "timeMs"]
            TAG_FIELD_NUMBER: _ClassVar[int]
            VALUE_FIELD_NUMBER: _ClassVar[int]
            TIMEMS_FIELD_NUMBER: _ClassVar[int]
            tag: str
            value: str
            timeMs: int
            def __init__(self, tag: _Optional[str] = ..., value: _Optional[str] = ..., timeMs: _Optional[int] = ...) -> None: ...
        class Statistic(_message.Message):
            __slots__ = ["tag", "count", "sum"]
            TAG_FIELD_NUMBER: _ClassVar[int]
            COUNT_FIELD_NUMBER: _ClassVar[int]
            SUM_FIELD_NUMBER: _ClassVar[int]
            tag: str
            count: int
            sum: float
            def __init__(self, tag: _Optional[str] = ..., count: _Optional[int] = ..., sum: _Optional[float] = ...) -> None: ...
        BUILD_FIELD_NUMBER: _ClassVar[int]
        LASTCHECKINMS_FIELD_NUMBER: _ClassVar[int]
        EVENT_FIELD_NUMBER: _ClassVar[int]
        STAT_FIELD_NUMBER: _ClassVar[int]
        REQUESTEDGROUP_FIELD_NUMBER: _ClassVar[int]
        CELLOPERATOR_FIELD_NUMBER: _ClassVar[int]
        SIMOPERATOR_FIELD_NUMBER: _ClassVar[int]
        ROAMING_FIELD_NUMBER: _ClassVar[int]
        USERNUMBER_FIELD_NUMBER: _ClassVar[int]
        build: CheckinRequest.Checkin.Build
        lastCheckinMs: int
        event: _containers.RepeatedCompositeFieldContainer[CheckinRequest.Checkin.Event]
        stat: _containers.RepeatedCompositeFieldContainer[CheckinRequest.Checkin.Statistic]
        requestedGroup: _containers.RepeatedScalarFieldContainer[str]
        cellOperator: str
        simOperator: str
        roaming: str
        userNumber: int
        def __init__(self, build: _Optional[_Union[CheckinRequest.Checkin.Build, _Mapping]] = ..., lastCheckinMs: _Optional[int] = ..., event: _Optional[_Iterable[_Union[CheckinRequest.Checkin.Event, _Mapping]]] = ..., stat: _Optional[_Iterable[_Union[CheckinRequest.Checkin.Statistic, _Mapping]]] = ..., requestedGroup: _Optional[_Iterable[str]] = ..., cellOperator: _Optional[str] = ..., simOperator: _Optional[str] = ..., roaming: _Optional[str] = ..., userNumber: _Optional[int] = ...) -> None: ...
    class DeviceConfig(_message.Message):
        __slots__ = ["touchScreen", "keyboardType", "navigation", "screenLayout", "hasHardKeyboard", "hasFiveWayNavigation", "densityDpi", "glEsVersion", "sharedLibrary", "availableFeature", "nativePlatform", "widthPixels", "heightPixels", "locale", "glExtension", "deviceClass", "maxApkDownloadSizeMb"]
        TOUCHSCREEN_FIELD_NUMBER: _ClassVar[int]
        KEYBOARDTYPE_FIELD_NUMBER: _ClassVar[int]
        NAVIGATION_FIELD_NUMBER: _ClassVar[int]
        SCREENLAYOUT_FIELD_NUMBER: _ClassVar[int]
        HASHARDKEYBOARD_FIELD_NUMBER: _ClassVar[int]
        HASFIVEWAYNAVIGATION_FIELD_NUMBER: _ClassVar[int]
        DENSITYDPI_FIELD_NUMBER: _ClassVar[int]
        GLESVERSION_FIELD_NUMBER: _ClassVar[int]
        SHAREDLIBRARY_FIELD_NUMBER: _ClassVar[int]
        AVAILABLEFEATURE_FIELD_NUMBER: _ClassVar[int]
        NATIVEPLATFORM_FIELD_NUMBER: _ClassVar[int]
        WIDTHPIXELS_FIELD_NUMBER: _ClassVar[int]
        HEIGHTPIXELS_FIELD_NUMBER: _ClassVar[int]
        LOCALE_FIELD_NUMBER: _ClassVar[int]
        GLEXTENSION_FIELD_NUMBER: _ClassVar[int]
        DEVICECLASS_FIELD_NUMBER: _ClassVar[int]
        MAXAPKDOWNLOADSIZEMB_FIELD_NUMBER: _ClassVar[int]
        touchScreen: int
        keyboardType: int
        navigation: int
        screenLayout: int
        hasHardKeyboard: bool
        hasFiveWayNavigation: bool
        densityDpi: int
        glEsVersion: int
        sharedLibrary: _containers.RepeatedScalarFieldContainer[str]
        availableFeature: _containers.RepeatedScalarFieldContainer[str]
        nativePlatform: _containers.RepeatedScalarFieldContainer[str]
        widthPixels: int
        heightPixels: int
        locale: _containers.RepeatedScalarFieldContainer[str]
        glExtension: _containers.RepeatedScalarFieldContainer[str]
        deviceClass: int
        maxApkDownloadSizeMb: int
        def __init__(self, touchScreen: _Optional[int] = ..., keyboardType: _Optional[int] = ..., navigation: _Optional[int] = ..., screenLayout: _Optional[int] = ..., hasHardKeyboard: bool = ..., hasFiveWayNavigation: bool = ..., densityDpi: _Optional[int] = ..., glEsVersion: _Optional[int] = ..., sharedLibrary: _Optional[_Iterable[str]] = ..., availableFeature: _Optional[_Iterable[str]] = ..., nativePlatform: _Optional[_Iterable[str]] = ..., widthPixels: _Optional[int] = ..., heightPixels: _Optional[int] = ..., locale: _Optional[_Iterable[str]] = ..., glExtension: _Optional[_Iterable[str]] = ..., deviceClass: _Optional[int] = ..., maxApkDownloadSizeMb: _Optional[int] = ...) -> None: ...
    IMEI_FIELD_NUMBER: _ClassVar[int]
    ANDROIDID_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    CHECKIN_FIELD_NUMBER: _ClassVar[int]
    DESIREDBUILD_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    LOGGINGID_FIELD_NUMBER: _ClassVar[int]
    MARKETCHECKIN_FIELD_NUMBER: _ClassVar[int]
    MACADDRESS_FIELD_NUMBER: _ClassVar[int]
    MEID_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTCOOKIE_FIELD_NUMBER: _ClassVar[int]
    TIMEZONE_FIELD_NUMBER: _ClassVar[int]
    SECURITYTOKEN_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    OTACERT_FIELD_NUMBER: _ClassVar[int]
    SERIAL_FIELD_NUMBER: _ClassVar[int]
    ESN_FIELD_NUMBER: _ClassVar[int]
    DEVICECONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    MACADDRESSTYPE_FIELD_NUMBER: _ClassVar[int]
    FRAGMENT_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    USERSERIALNUMBER_FIELD_NUMBER: _ClassVar[int]
    imei: str
    androidId: int
    digest: str
    checkin: CheckinRequest.Checkin
    desiredBuild: str
    locale: str
    loggingId: int
    marketCheckin: str
    macAddress: _containers.RepeatedScalarFieldContainer[str]
    meid: str
    accountCookie: _containers.RepeatedScalarFieldContainer[str]
    timeZone: str
    securityToken: int
    version: int
    otaCert: _containers.RepeatedScalarFieldContainer[str]
    serial: str
    esn: str
    deviceConfiguration: CheckinRequest.DeviceConfig
    macAddressType: _containers.RepeatedScalarFieldContainer[str]
    fragment: int
    userName: str
    userSerialNumber: int
    def __init__(self, imei: _Optional[str] = ..., androidId: _Optional[int] = ..., digest: _Optional[str] = ..., checkin: _Optional[_Union[CheckinRequest.Checkin, _Mapping]] = ..., desiredBuild: _Optional[str] = ..., locale: _Optional[str] = ..., loggingId: _Optional[int] = ..., marketCheckin: _Optional[str] = ..., macAddress: _Optional[_Iterable[str]] = ..., meid: _Optional[str] = ..., accountCookie: _Optional[_Iterable[str]] = ..., timeZone: _Optional[str] = ..., securityToken: _Optional[int] = ..., version: _Optional[int] = ..., otaCert: _Optional[_Iterable[str]] = ..., serial: _Optional[str] = ..., esn: _Optional[str] = ..., deviceConfiguration: _Optional[_Union[CheckinRequest.DeviceConfig, _Mapping]] = ..., macAddressType: _Optional[_Iterable[str]] = ..., fragment: _Optional[int] = ..., userName: _Optional[str] = ..., userSerialNumber: _Optional[int] = ...) -> None: ...

class CheckinResponse(_message.Message):
    __slots__ = ["statsOk", "intent", "timeMs", "digest", "setting", "marketOk", "androidId", "securityToken", "settingsDiff", "deleteSetting", "versionInfo", "deviceDataVersionInfo"]
    class Intent(_message.Message):
        __slots__ = ["action", "dataUri", "mimeType", "javaClass", "extra"]
        class Extra(_message.Message):
            __slots__ = ["name", "value"]
            NAME_FIELD_NUMBER: _ClassVar[int]
            VALUE_FIELD_NUMBER: _ClassVar[int]
            name: str
            value: str
            def __init__(self, name: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
        ACTION_FIELD_NUMBER: _ClassVar[int]
        DATAURI_FIELD_NUMBER: _ClassVar[int]
        MIMETYPE_FIELD_NUMBER: _ClassVar[int]
        JAVACLASS_FIELD_NUMBER: _ClassVar[int]
        EXTRA_FIELD_NUMBER: _ClassVar[int]
        action: str
        dataUri: str
        mimeType: str
        javaClass: str
        extra: _containers.RepeatedCompositeFieldContainer[CheckinResponse.Intent.Extra]
        def __init__(self, action: _Optional[str] = ..., dataUri: _Optional[str] = ..., mimeType: _Optional[str] = ..., javaClass: _Optional[str] = ..., extra: _Optional[_Iterable[_Union[CheckinResponse.Intent.Extra, _Mapping]]] = ...) -> None: ...
    class GservicesSetting(_message.Message):
        __slots__ = ["name", "value"]
        NAME_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        name: bytes
        value: bytes
        def __init__(self, name: _Optional[bytes] = ..., value: _Optional[bytes] = ...) -> None: ...
    STATSOK_FIELD_NUMBER: _ClassVar[int]
    INTENT_FIELD_NUMBER: _ClassVar[int]
    TIMEMS_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    SETTING_FIELD_NUMBER: _ClassVar[int]
    MARKETOK_FIELD_NUMBER: _ClassVar[int]
    ANDROIDID_FIELD_NUMBER: _ClassVar[int]
    SECURITYTOKEN_FIELD_NUMBER: _ClassVar[int]
    SETTINGSDIFF_FIELD_NUMBER: _ClassVar[int]
    DELETESETTING_FIELD_NUMBER: _ClassVar[int]
    VERSIONINFO_FIELD_NUMBER: _ClassVar[int]
    DEVICEDATAVERSIONINFO_FIELD_NUMBER: _ClassVar[int]
    statsOk: bool
    intent: _containers.RepeatedCompositeFieldContainer[CheckinResponse.Intent]
    timeMs: int
    digest: str
    setting: _containers.RepeatedCompositeFieldContainer[CheckinResponse.GservicesSetting]
    marketOk: bool
    androidId: int
    securityToken: int
    settingsDiff: bool
    deleteSetting: _containers.RepeatedScalarFieldContainer[str]
    versionInfo: str
    deviceDataVersionInfo: str
    def __init__(self, statsOk: bool = ..., intent: _Optional[_Iterable[_Union[CheckinResponse.Intent, _Mapping]]] = ..., timeMs: _Optional[int] = ..., digest: _Optional[str] = ..., setting: _Optional[_Iterable[_Union[CheckinResponse.GservicesSetting, _Mapping]]] = ..., marketOk: bool = ..., androidId: _Optional[int] = ..., securityToken: _Optional[int] = ..., settingsDiff: bool = ..., deleteSetting: _Optional[_Iterable[str]] = ..., versionInfo: _Optional[str] = ..., deviceDataVersionInfo: _Optional[str] = ...) -> None: ...
