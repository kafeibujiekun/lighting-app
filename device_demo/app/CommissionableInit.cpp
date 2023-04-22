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

#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

#include "CommissionableInit.h"

using namespace chip::DeviceLayer;

CHIP_ERROR InitCommissionableDataProvider(DeviceCommissionableDataProvider & provider)
{
    chip::Optional<uint32_t> setupPasscode;
    chip::Optional<uint16_t> discriminator;
    uint32_t defaultPasscode = 20202021;
    uint16_t defaultDiscriminator = 3840;
    // Default to minimum PBKDF iterations
    uint32_t spake2pIterationCount = chip::Crypto::kSpake2p_Min_PBKDF_Iterations;

    setupPasscode.SetValue(defaultPasscode);

    ChipLogError(Support, "PASE PBKDF iterations set to %u", static_cast<unsigned>(spake2pIterationCount));

    return provider.Init(spake2pIterationCount, setupPasscode, defaultDiscriminator);
}

CHIP_ERROR InitConfigurationManager(ConfigurationManagerImpl & configManager)
{
    configManager.StoreVendorId(65521);

    configManager.StoreProductId(32768);

    configManager.StoreHardwareVersion(1234);

    return CHIP_NO_ERROR;
}

