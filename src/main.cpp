//
// Created by PinkySmile on 31/10/2020
//

#include <SokuLib.hpp>
#include <Shlwapi.h>

#ifndef _DEBUG
#define printf(...)
#define puts(...)
#endif

static void (__fastcall *s_origInitPlayer)(SokuLib::CharacterManager *);
static char profilePath[1024 + MAX_PATH];

void __fastcall initPlayer(SokuLib::CharacterManager *This)
{
	s_origInitPlayer(This);

	char *name;
	char *index = (char *)&This->isRightPlayer;

	if (SokuLib::mainMode == SokuLib::BATTLE_MODE_VSSERVER || SokuLib::mainMode == SokuLib::BATTLE_MODE_VSCLIENT)
		name = SokuLib::getNetObject().profile1name + (*index * 32);
	else
		name = ((SokuLib::Profile *(*)(int index))0x43E010)(*index)->name;
	printf("Setting HP for %i (%s)\n", *index, name);

	auto end = strrchr(name, '@');
	char moduleKeys[1024];

	*(short *)&This->objectBase.offset_0x186 = GetPrivateProfileInt("Default", "HP", 10000, profilePath);
	printf("Default is %i\n", *(short *)&This->objectBase.offset_0x186);
	if (!end) {
		puts("No suffix found, using default");
		return;
	}
	end++;
	GetPrivateProfileString("HP", nullptr, nullptr, moduleKeys, sizeof(moduleKeys), profilePath);
	for (char *key = moduleKeys; *key; key += strlen(key) + 1) {
		if (strcmp(key, end) != 0)
			continue;
		*(short *)&This->objectBase.offset_0x186 = GetPrivateProfileInt("HP", key, 10000, profilePath);
		printf("Found for %s !\n", key);
		break;
	}
	printf("HP is %i\n", *(short *)&This->objectBase.offset_0x186);
}

// We check if the game version is what we target (in our case, Soku 1.10a).
extern "C" __declspec(dllexport) bool CheckVersion(const BYTE hash[16])
{
	return memcmp(hash, SokuLib::targetHash, sizeof(SokuLib::targetHash)) == 0;
}

// Called when the mod loader is ready to initialize this module.
// All hooks should be placed here. It's also a good moment to load settings from the ini.
extern "C" __declspec(dllexport) bool Initialize(HMODULE hMyModule, HMODULE hParentModule)
{
	DWORD old;

	GetModuleFileName(hMyModule, profilePath, 1024);
	PathRemoveFileSpec(profilePath);
	PathAppend(profilePath, "HandicapMod.ini");

#ifdef _DEBUG
	FILE *_;

	AllocConsole();
	freopen_s(&_, "CONOUT$", "w", stdout);
	freopen_s(&_, "CONOUT$", "w", stderr);
#endif

	printf("Config is %s\n", profilePath);
	VirtualProtect((PVOID)TEXT_SECTION_OFFSET, TEXT_SECTION_SIZE, PAGE_EXECUTE_WRITECOPY, &old);
	const unsigned char patch[] = {
		0x8B, 0x86, 0x86, 0x01, 0x00, 0x00,  // mov eax,[esi+00000186]
		0x90,                                // nop
		0x90,                                // nop
		0x90,                                // nop
		0x90,                                // nop
		0x90,                                // nop
		0x90,                                // nop
	};
	memcpy((void *)0x46BCA4, patch, sizeof(patch));
	s_origInitPlayer = SokuLib::TamperNearJmpOpr(0x46DE31, initPlayer);
	VirtualProtect((PVOID)TEXT_SECTION_OFFSET, TEXT_SECTION_SIZE, old, &old);

	FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
	return true;
}

extern "C" int APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved)
{
	return TRUE;
}

// New mod loader functions
// Loading priority. Mods are loaded in order by ascending level of priority (the highest first).
// When 2 mods define the same loading priority the loading order is undefined.
extern "C" __declspec(dllexport) int getPriority()
{
	return 0;
}

// Not yet implemented in the mod loader, subject to change
// SokuModLoader::IValue **getConfig();
// void freeConfig(SokuModLoader::IValue **v);
// bool commitConfig(SokuModLoader::IValue *);
// const char *getFailureReason();
// bool hasChainedHooks();
// void unHook();