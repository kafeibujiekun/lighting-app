#pragma once

#include <lib/support/EnforceFormat.h>
#include <platform/DeviceInfoProvider.h>

namespace chip {
namespace DeviceLayer {

class LightDeviceInfoProvider : public DeviceInfoProvider
{
public:
    LightDeviceInfoProvider() = default;
    ~LightDeviceInfoProvider() override {}

    // Iterators
    FixedLabelIterator * IterateFixedLabel(EndpointId endpoint) override;
    UserLabelIterator * IterateUserLabel(EndpointId endpoint) override;
    SupportedLocalesIterator * IterateSupportedLocales() override;
    SupportedCalendarTypesIterator * IterateSupportedCalendarTypes() override;

    static LightDeviceInfoProvider & GetDefaultInstance();

protected:
    class FixedLabelIteratorImpl : public FixedLabelIterator
    {
    public:
        FixedLabelIteratorImpl(EndpointId endpoint);
        size_t Count() override;
        bool Next(FixedLabelType & output) override;
        void Release() override { chip::Platform::Delete(this); }

    private:
        EndpointId mEndpoint = 0;
        size_t mIndex        = 0;
        char mFixedLabelNameBuf[kMaxLabelNameLength + 1];
        char mFixedLabelValueBuf[kMaxLabelValueLength + 1];
    };

    class UserLabelIteratorImpl : public UserLabelIterator
    {
    public:
        UserLabelIteratorImpl(LightDeviceInfoProvider & provider, EndpointId endpoint);
        size_t Count() override { return mTotal; }
        bool Next(UserLabelType & output) override;
        void Release() override { chip::Platform::Delete(this); }

    private:
        LightDeviceInfoProvider & mProvider;
        EndpointId mEndpoint = 0;
        size_t mIndex        = 0;
        size_t mTotal        = 0;
        char mUserLabelNameBuf[kMaxLabelNameLength + 1];
        char mUserLabelValueBuf[kMaxLabelValueLength + 1];
    };

    class SupportedLocalesIteratorImpl : public SupportedLocalesIterator
    {
    public:
        SupportedLocalesIteratorImpl() = default;
        size_t Count() override;
        bool Next(CharSpan & output) override;
        void Release() override { chip::Platform::Delete(this); }

    private:
        size_t mIndex = 0;
        char mActiveLocaleBuf[kMaxActiveLocaleLength + 1];
    };

    class SupportedCalendarTypesIteratorImpl : public SupportedCalendarTypesIterator
    {
    public:
        SupportedCalendarTypesIteratorImpl() = default;
        size_t Count() override;
        bool Next(CalendarType & output) override;
        void Release() override { chip::Platform::Delete(this); }

    private:
        size_t mIndex = 0;
    };

    CHIP_ERROR SetUserLabelLength(EndpointId endpoint, size_t val) override;
    CHIP_ERROR GetUserLabelLength(EndpointId endpoint, size_t & val) override;
    CHIP_ERROR SetUserLabelAt(EndpointId endpoint, size_t index, const UserLabelType & userLabel) override;
    CHIP_ERROR DeleteUserLabelAt(EndpointId endpoint, size_t index) override;

private:
    static constexpr size_t UserLabelTLVMaxSize() { return TLV::EstimateStructOverhead(kMaxLabelNameLength, kMaxLabelValueLength); }
};

} // namespace DeviceLayer
} // namespace chip
