#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(
   HANDLE hModule,	   // Handle to DLL module 
   DWORD ul_reason_for_call, 
   LPVOID lpReserved )     // Reserved
{
   switch ( ul_reason_for_call )
   {
      case 1:
      printf("DLL_PROCESS_ATTACHED\n");
      break;
      
      case 2:
      printf("DLL_THREAD_ATTACHED\n");
      break;
      
      case 3:
      printf("DLL_THREAD_DETACH\n");
      break;
      
      case 0:
      printf("DLL_PROCESS_DETACH\n");
      break;
   }
   return TRUE;
}