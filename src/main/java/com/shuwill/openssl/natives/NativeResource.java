package com.shuwill.openssl.natives;

import com.shuwill.openssl.natives.pointer.Pointer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class NativeResource {

    private static final Map<UUID, List<Pointer>> POINTERS = new HashMap<>();

    public static void init(UUID uuid) {
        POINTERS.put(uuid, new ArrayList<>());
    }

    public static void add(UUID uuid, Pointer pointer) {
        POINTERS.get(uuid).add(pointer);
    }

    public static void clear(UUID uuid) {
        try {
            if (POINTERS.get(uuid) == null) {
                return;
            }
            for (Pointer pointer : POINTERS.get(uuid)) {
                try {
                    pointer.close();
                } catch (Error | Exception ignore) {
                }
            }
        } finally {
            POINTERS.remove(uuid);
        }
    }
}
