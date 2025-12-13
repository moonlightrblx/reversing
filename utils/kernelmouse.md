## Structs
```cpp
typedef struct _movemouse
{
	long x;
	long y;
	unsigned short button_flags;
} movemouse, * MouseMovementStruct;


typedef struct _MOUSE_INPUT_DATA {
	USHORT UnitId;
	USHORT Flags;
	union {
		ULONG Buttons;
		struct {
			USHORT ButtonFlags;
			USHORT ButtonData;
		};
	};
	ULONG RawButtons;
	LONG LastX;
	LONG LastY;
	ULONG ExtraInformation;
} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

typedef VOID(*PMOUSE_CLASS_SERVICE_CALLBACK)(
	PVOID Context,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
	);


```
## Init function (call once at driver entry)
```cpp
PMOUSE_CLASS_SERVICE_CALLBACK g_MouseCallback = NULL;
PVOID g_MouseContext = NULL;

#define MAX_POINTER_CLASSES 10

NTSTATUS InitMouseInjection() {
	UNICODE_STRING mouseClassDeviceName;
	PFILE_OBJECT fileObject = NULL;
	PDEVICE_OBJECT deviceObject = NULL;
	NTSTATUS status = STATUS_NOT_FOUND;

	WCHAR deviceNameBuffer[64];

	for (int i = 0; i < MAX_POINTER_CLASSES; i++) {
		RtlStringCchPrintfW(deviceNameBuffer, sizeof(deviceNameBuffer) / sizeof(WCHAR), L"\\Device\\PointerClass%d", i);
		RtlInitUnicodeString(&mouseClassDeviceName, deviceNameBuffer);

		status = IoGetDeviceObjectPointer(&mouseClassDeviceName, FILE_READ_DATA, &fileObject, &deviceObject);
		if (NT_SUCCESS(status)) {
			if (deviceObject && fileObject) {
				// try to get the mouse extension and check if classService callback exists
				typedef struct _MOUSE_DEVICE_EXTENSION {
					PMOUSE_CLASS_SERVICE_CALLBACK ClassService;
					PVOID ClassDeviceObject;
					PVOID ClassContext;
				} MOUSE_DEVICE_EXTENSION, * PMOUSE_DEVICE_EXTENSION;

				PMOUSE_DEVICE_EXTENSION mouseExt = (PMOUSE_DEVICE_EXTENSION)deviceObject->DeviceExtension;

				if (mouseExt && mouseExt->ClassService) {
		
					g_MouseCallback = mouseExt->ClassService;
					g_MouseContext = mouseExt->ClassContext;

				//	DbgPrintEx(0, 0, "mouse injection initialized: callback=%p context=%p\n", g_MouseCallback, g_MouseContext);

					ObDereferenceObject(fileObject);
					return STATUS_SUCCESS;
				}
			}
			ObDereferenceObject(fileObject);
		}
	}

	DbgPrintEx(0, 0, "Failed to find valid mouse device.\n");
	return status;
}
```
### MouseMove Function (same args as mouse_event)
```cpp
NTSTATUS InjectMouseMovement(LONG x, LONG y, USHORT buttonFlags) {
	if (!g_MouseCallback)
		return STATUS_UNSUCCESSFUL;

	MOUSE_INPUT_DATA mid = { 0 };
	ULONG consumed;

	mid.UnitId = 0;
	mid.Flags = MOUSE_MOVE_RELATIVE;
	mid.LastX = x;
	mid.LastY = y;
	mid.ButtonFlags = buttonFlags;
	mid.ExtraInformation = 0;

	g_MouseCallback(g_MouseContext, &mid, &mid + 1, &consumed);

	return STATUS_SUCCESS;
}

```

### Iotcl handling
```cpp
else if (code == code_mouse) {
			if (size == sizeof(_movemouse)) {
				MouseMovementStruct req = (MouseMovementStruct)(irp->AssociatedIrp.SystemBuffer);
				InjectMouseMovement(req->x, req->y, req->button_flags);
				bytes = sizeof(_movemouse);
			}
			else
			{
				status = STATUS_INFO_LENGTH_MISMATCH;
				bytes = 0;
			}
		}
```
