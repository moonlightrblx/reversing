#pragma once
#include <Windows.h>

template <typename hook_type>
_declspec(noinline) hook_type vmt_hook(void* address, void* hook_function, int index, void** ret = nullptr) {
	uintptr_t* original_vtable = *(uintptr_t**)address;

	int methodCount = 0;
	while (original_vtable[methodCount])
		++methodCount;

	uintptr_t* shadow_vtable = reinterpret_cast<uintptr_t*>(
		IFH(VirtualAlloc)(nullptr, methodCount * sizeof(uintptr_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
		);
	if (!shadow_vtable) {
		return hook_type(original_vtable[index]);
	}

	memcpy(shadow_vtable, original_vtable, methodCount * sizeof(uintptr_t));

	if (ret)
		*ret = reinterpret_cast<void*>(original_vtable[index]);

	shadow_vtable[index] = reinterpret_cast<uintptr_t>(hook_function);

	DWORD oldProtect;
	IFH(VirtualProtect)(shadow_vtable, methodCount * sizeof(uintptr_t), PAGE_EXECUTE_READ, &oldProtect);

	*(uintptr_t**)address = shadow_vtable;

	return hook_type(original_vtable[index]);
}
