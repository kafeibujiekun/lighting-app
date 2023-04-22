/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "DeviceCommissionableDataProvider.h"

#include <string.h>

#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>
#include <lib/support/logging/CHIPLogging.h>

using namespace chip::Crypto;

namespace {

CHIP_ERROR GeneratePaseSalt(std::vector<uint8_t> & spake2pSaltVector)
{
    constexpr size_t kSaltLen = kSpake2p_Max_PBKDF_Salt_Length;
    spake2pSaltVector.resize(kSaltLen);
    return DRBG_get_bytes(spake2pSaltVector.data(), spake2pSaltVector.size());
}

} // namespace

CHIP_ERROR DeviceCommissionableDataProvider::Init(uint32_t spake2pIterationCount,
                                                 chip::Optional<uint32_t> setupPasscode,
                                                 uint16_t discriminator)
{
    VerifyOrReturnError(mIsInitialized == false, CHIP_ERROR_WELL_UNINITIALIZED);

    if (discriminator > chip::kMaxDiscriminatorValue)
    {
        ChipLogError(Support, "Discriminator value invalid: %u", static_cast<unsigned>(discriminator));
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    if ((spake2pIterationCount < kSpake2p_Min_PBKDF_Iterations) || (spake2pIterationCount > kSpake2p_Max_PBKDF_Iterations))
    {
        ChipLogError(Support, "PASE Iteration count invalid: %u", static_cast<unsigned>(spake2pIterationCount));
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    CHIP_ERROR err;
    Spake2pVerifier passcodeVerifier;
    std::vector<uint8_t> serializedPasscodeVerifier(kSpake2p_VerifierSerialized_Length);
    bool havePasscode = setupPasscode.HasValue();

    ChipLogProgress(Support, "generating a PASE salt");
    std::vector<uint8_t> spake2pSaltVector;
    err = GeneratePaseSalt(spake2pSaltVector);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Support, "Failed to generate PASE salt: %" CHIP_ERROR_FORMAT, err.Format());
        return err;
    }

    chip::MutableByteSpan saltSpan{ spake2pSaltVector.data(), spake2pSaltVector.size() };

    size_t spake2pSaltLength = spake2pSaltVector.size();
    if ((spake2pSaltLength < kSpake2p_Min_PBKDF_Salt_Length) || (spake2pSaltLength > kSpake2p_Max_PBKDF_Salt_Length))
    {
        ChipLogError(Support, "PASE salt length invalid: %u", static_cast<unsigned>(spake2pSaltLength));
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    if (havePasscode)
    {
        err = passcodeVerifier.Generate(spake2pIterationCount, saltSpan, setupPasscode.Value());
        if (err != CHIP_NO_ERROR)
        {
            ChipLogError(Support, "Failed to generate PASE verifier from passcode: %" CHIP_ERROR_FORMAT, err.Format());
            return err;
        }

        chip::MutableByteSpan verifierSpan{ serializedPasscodeVerifier.data(), serializedPasscodeVerifier.size() };
        err = passcodeVerifier.Serialize(verifierSpan);
        if (err != CHIP_NO_ERROR)
        {
            ChipLogError(Support, "Failed to serialize PASE verifier from passcode: %" CHIP_ERROR_FORMAT, err.Format());
            return err;
        }
    }
    else
    {
        ChipLogError(Support, "no passcode: cannot produce final verifier");
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    mDiscriminator          = discriminator;
    mSerializedPaseVerifier = std::move(serializedPasscodeVerifier);
    mPaseSalt               = std::move(spake2pSaltVector);
    mPaseIterationCount     = spake2pIterationCount;
    if (havePasscode)
    {
        mSetupPasscode.SetValue(setupPasscode.Value());
    }
    mIsInitialized = true;

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceCommissionableDataProvider::GetSetupDiscriminator(uint16_t & setupDiscriminator)
{
    VerifyOrReturnError(mIsInitialized == true, CHIP_ERROR_WELL_UNINITIALIZED);
    setupDiscriminator = mDiscriminator;
    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceCommissionableDataProvider::GetSpake2pIterationCount(uint32_t & iterationCount)
{
    VerifyOrReturnError(mIsInitialized == true, CHIP_ERROR_WELL_UNINITIALIZED);
    iterationCount = mPaseIterationCount;
    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceCommissionableDataProvider::GetSpake2pSalt(chip::MutableByteSpan & saltBuf)
{
    VerifyOrReturnError(mIsInitialized == true, CHIP_ERROR_WELL_UNINITIALIZED);

    VerifyOrReturnError(saltBuf.size() >= kSpake2p_Max_PBKDF_Salt_Length, CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(saltBuf.data(), mPaseSalt.data(), mPaseSalt.size());
    saltBuf.reduce_size(mPaseSalt.size());

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceCommissionableDataProvider::GetSpake2pVerifier(chip::MutableByteSpan & verifierBuf, size_t & outVerifierLen)
{
    VerifyOrReturnError(mIsInitialized == true, CHIP_ERROR_WELL_UNINITIALIZED);

    // By now, serialized verifier from Init should be correct size
    VerifyOrReturnError(mSerializedPaseVerifier.size() == kSpake2p_VerifierSerialized_Length, CHIP_ERROR_INTERNAL);

    outVerifierLen = mSerializedPaseVerifier.size();
    VerifyOrReturnError(verifierBuf.size() >= outVerifierLen, CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(verifierBuf.data(), mSerializedPaseVerifier.data(), mSerializedPaseVerifier.size());
    verifierBuf.reduce_size(mSerializedPaseVerifier.size());

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceCommissionableDataProvider::GetSetupPasscode(uint32_t & setupPasscode)
{
    VerifyOrReturnError(mIsInitialized == true, CHIP_ERROR_WELL_UNINITIALIZED);

    // Pretend not implemented if we don't have a passcode value externally set
    if (!mSetupPasscode.HasValue())
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }

    setupPasscode = mSetupPasscode.Value();
    return CHIP_NO_ERROR;
}
