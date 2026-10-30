// Stand-in for the client-only <game/CVehicle.h> that Shared/sdk/net/SyncStructures.h reaches for in a
// server-style build. The real header drags in MSVC-only enum forward declarations (CEntity.h) that clang
// rejects; SyncStructures.h only needs the damage-manager limits and the siren constants below, whose
// values mirror Client/sdk/game/CVehicle.h.
#pragma once
#include "../../Client/sdk/game/CDamageManager.h"

#define SIREN_TYPE_FIRST 1
#define SIREN_TYPE_LAST  6
#define SIREN_ID_MAX     7
#define SIREN_COUNT_MAX  8
