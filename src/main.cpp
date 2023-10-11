//
// Created by PinkySmile on 31/10/2020
//

#include <SokuLib.hpp>
#include <Shlwapi.h>

#ifndef _DEBUG
#define printf(...)
#define puts(...)
#endif

static void (__stdcall *s_origLoadDeckData)(char *, void *, SokuLib::DeckInfo &, int, SokuLib::Dequeue<short> &);
static void (__fastcall *s_origInitPlayer)(SokuLib::CharacterManager *);
static char profilePath[1024 + MAX_PATH];
static char *end;

void __fastcall initPlayer(SokuLib::CharacterManager *This)
{

	char *name;
	char *index = (char *)&This->isRightPlayer;

	if (
		SokuLib::mainMode == SokuLib::BATTLE_MODE_VSSERVER ||
		SokuLib::mainMode == SokuLib::BATTLE_MODE_VSCLIENT ||
		SokuLib::mainMode == SokuLib::BATTLE_MODE_VSWATCH
	)
		name = SokuLib::getNetObject().profile1name + (*index * 32);
	else
		name = ((SokuLib::Profile *(*)(int index))0x43E010)(*index)->name;
	end = strrchr(name, '@');
	if (end)
		end++;
	s_origInitPlayer(This);
	printf("Setting HP for %i (%s)\n", *index, name);

	char moduleKeys[1024];

	*(short *)&This->objectBase.offset_0x186 = GetPrivateProfileInt("Default", "HP", 10000, profilePath);
	printf("Default is %i\n", *(short *)&This->objectBase.offset_0x186);
	if (!end) {
		puts("No suffix found, using default\n");
		return;
	}
	GetPrivateProfileString("HP", nullptr, nullptr, moduleKeys, sizeof(moduleKeys), profilePath);
	for (char *key = moduleKeys; *key; key += strlen(key) + 1) {
		if (strcmp(key, end) != 0)
			continue;
		*(short *)&This->objectBase.offset_0x186 = GetPrivateProfileInt("HP", key, 10000, profilePath);
		printf("Found for %s!\n", key);
		break;
	}
	printf("HP is %i\n\n", *(short *)&This->objectBase.offset_0x186);
}

void __stdcall loadDeckData(char *charName, void *csvFile, SokuLib::DeckInfo &deck, int param4, SokuLib::Dequeue<short> &newDeck)
{
	s_origLoadDeckData(charName, csvFile, deck, param4, newDeck);
	puts("Setting cards");
	if (newDeck.size == 0) {
		puts("Invalid deck...");
		return;
	}

	char moduleKeys[1024];
	int count = GetPrivateProfileInt("Default", "Cards", 20, profilePath);

	printf("Default is %i\n", count);
	if (end) {
		GetPrivateProfileString("Cards", nullptr, nullptr, moduleKeys, sizeof(moduleKeys), profilePath);
		for (char *key = moduleKeys; *key; key += strlen(key) + 1) {
			if (strcmp(key, end) != 0)
				continue;
			count = GetPrivateProfileInt("Cards", key, 20, profilePath);
			printf("Found for %s!\n", key);
			break;
		}
	} else
		puts("No suffix found, using default");
	printf("Player has %i cards\n", count);
	if (count == newDeck.size) {
		puts("Job done!");
		return;
	}

	std::vector<unsigned short> fakeDeck;
	std::vector<unsigned short> actualDeck;
	SokuLib::Dequeue<short> *newDeckStar = &newDeck + 1;

	fakeDeck.reserve(newDeck.size);
	actualDeck.reserve(count);
	while (actualDeck.size() != count) {
		if (fakeDeck.empty())
			for (int i = 0; i < newDeck.size; i++)
				fakeDeck.push_back(newDeck[i]);

		auto it = fakeDeck.begin() + rand() % fakeDeck.size();

		actualDeck.push_back(*it);
		fakeDeck.erase(it);
	}
	newDeck.clear();
	for (auto card : actualDeck)
		newDeck.push_back(card);
	newDeckStar->clear();
	while (newDeckStar->size != newDeck.size)
		newDeckStar->push_back(newDeck[newDeckStar->size]);
	printf("%p\n", &newDeck.size);
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
	srand(time(nullptr));

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

	const unsigned char calmPatch[] = {
		0x8D, 0x41, 0x05,                         // LEA EAX, [ECX + 05]
		0x66, 0x8B, 0x8E, 0x86, 0x01, 0x00, 0x00, // MOV CX, [ESI + 00000186]
		0x66, 0x39, 0xC8,                         // CMP AX, CX
		0x7E, 0x03,                               // JLE th123.exe+88F98
		0x66, 0x89, 0xC8,                         // MOV AX, CX
		0x66, 0x89, 0x86, 0x84, 0x01, 0x00, 0x00, // MOV [ESI + 00000184], AX
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 // 8 NOP
	};
	memcpy((void *)0x488F86, calmPatch, sizeof(calmPatch));
	s_origInitPlayer = SokuLib::TamperNearJmpOpr(0x46DE31, initPlayer);
	s_origLoadDeckData = SokuLib::TamperNearJmpOpr(0x437D23, loadDeckData);
	memset((void *)0x435DA4, 0x90, 13);
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