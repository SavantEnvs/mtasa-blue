// Fuzz harness: MTA network sync structures (Shared/sdk/net/SyncStructures.h).
// The first two input bytes pick a structure and a bitstream protocol version; the rest is the
// packet payload fed to the structure's Read(). A successful Read is followed by Write() into a
// fresh stream and a re-read, which exercises the encode path on attacker-shaped values.
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <new>
#include <MockBitStream.h>
#include <net/SyncStructures.h>

namespace
{
    constexpr size_t kMaxPayload = 1024;

    // MockBitStream::WriteNormVector is a unit-test stand-in for RakNet's encoder and casts an unclamped
    // float to short (UB for NaN/inf). Production uses RakNet's, so keep non-finite input away from the mock.
    class FuzzBitStream : public MockBitStream
    {
    public:
        explicit FuzzBitStream(unsigned short version) : MockBitStream(version) {}
        void WriteNormVector(float x, float y, float z) override
        {
            if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z))
                x = y = z = 0.0f;
            MockBitStream::WriteNormVector(x, y, z);
        }
    };

    template <typename T, typename... Args>
    void Exercise(const uint8_t* payload, size_t size, uint16_t version, Args... args)
    {
        MockBitStream in(version);
        in.Write(reinterpret_cast<const char*>(payload), static_cast<int>(size));
        in.ResetReadPointer();

        alignas(T) unsigned char storage[sizeof(T)];
        std::memset(storage, 0, sizeof(storage));
        T* s = new (storage) T(args...);
        if (!s->Read(in))
        {
            s->~T();
            return;
        }

        FuzzBitStream out(version);
        s->Write(out);
        out.ResetReadPointer();

        alignas(T) unsigned char storage2[sizeof(T)];
        std::memset(storage2, 0, sizeof(storage2));
        T* s2 = new (storage2) T(args...);
        s2->Read(out);
        s2->~T();
        s->~T();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3)
        return -1;
    if (size > kMaxPayload)
        return -1;

    const uint8_t  which = data[0];
    const uint8_t  flags = data[1];
    const uint16_t first = static_cast<uint16_t>(eBitStreamVersion::Unk);
    const uint16_t last = static_cast<uint16_t>(eBitStreamVersion::Latest);
    const uint16_t version = static_cast<uint16_t>(first + (data[2] % (last - first + 1)));
    const uint8_t* payload = data + 3;
    const size_t   psize = size - 3;
    const bool     f0 = flags & 1, f1 = flags & 2, f2 = flags & 4, f3 = flags & 8, f4 = flags & 16;

#define CASE(n, ...) \
    case n:          \
        Exercise<__VA_ARGS__>(payload, psize, version); \
        break
    switch (which % 64)
    {
        CASE(0, SFloatSync<14, 10>);
        CASE(1, SFloatSync<7, 9>);
        CASE(2, SIntegerSync<unsigned short, 11>);
        CASE(3, SIntegerSync<int, 21>);
        CASE(4, SPlayerHealthSync);
        CASE(5, SPlayerArmorSync);
        CASE(6, SVehicleHealthSync);
        CASE(7, SLowPrecisionVehicleHealthSync);
        CASE(8, SObjectHealthSync);
        CASE(9, SPedStatSync);
        case 10: Exercise<SPositionSync>(payload, psize, version, f0); break;
        CASE(11, SPosition2DSync);
        CASE(12, SLowPrecisionPositionSync);
        case 13: Exercise<SRotationDegreesSync>(payload, psize, version, f0); break;
        case 14: Exercise<SRotationRadiansSync>(payload, psize, version, f0); break;
        CASE(15, SVelocitySync);
        CASE(16, SPlayerPuresyncFlags);
        CASE(17, SPedRotationSync);
        CASE(18, SCameraRotationSync);
        CASE(19, SKeysyncRotation);
        CASE(20, SVehiclePuresyncFlags);
        CASE(21, SDrivebyDirectionSync);
        CASE(22, SUnoccupiedVehicleSync);
        CASE(23, SKeysyncFlags);
        CASE(24, SFullKeysyncSync);
        CASE(25, SSmallKeysyncSync);
        CASE(26, SVehicleTurretSync);
        CASE(27, SDoorOpenRatioSync);
        CASE(28, SWeaponSlotSync);
        CASE(29, SWeaponTypeSync);
        case 30: Exercise<SWeaponAmmoSync>(payload, psize, version, static_cast<unsigned char>(flags), f0, f1); break;
        case 31: Exercise<SWeaponAimSync>(payload, psize, version, f0 ? 25.0f : 0.0f, f1); break;
        CASE(32, SBodypartSync);
        case 33: Exercise<SVehiclePartStateSync<MAX_DOORS, 3>>(payload, psize, version, f0); break;
        case 34: Exercise<SVehicleDamageSync>(payload, psize, version, f0, f1, f2, f3, f4); break;
        CASE(35, SVehiclePartStateSyncMethodeB<MAX_WHEELS, 2>);
        CASE(36, SVehicleDamageSyncMethodeB);
        CASE(37, SVehicleHandlingSync);
        CASE(38, SVehicleSirenAddSync);
        CASE(39, SVehicleSirenSync);
        CASE(40, SExplosionTypeSync);
        CASE(41, SMapInfoFlagsSync);
        CASE(42, SFunBugsStateSync);
        CASE(43, SWorldSpecialPropertiesStateSync);
        CASE(44, SQuitReasonSync);
        CASE(45, SEntityAlphaSync);
        CASE(46, SMarkerTypeSync);
        CASE(47, SPickupTypeSync);
        CASE(48, SColshapeTypeSync);
        case 49: Exercise<SColorSync>(payload, psize, version, SColor(0)); break;
        CASE(50, SOccupiedSeatSync);
        CASE(51, SPaintjobSync);
        CASE(52, SOverrideLightsSync);
        CASE(53, SLuaTypeSync);
        CASE(54, SMouseButtonSync);
        CASE(55, SHeatHazeSync);
        CASE(56, sWeaponPropertySync);
        CASE(57, SUnoccupiedPushSync);
        default:
            return -1;
    }
#undef CASE
    return 0;
}
