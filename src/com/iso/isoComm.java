package com.iso;

import gpjshellbridge.GpjShellBridge;

public class isoComm {
    public static byte[] transceive(byte[] data)
    {
    	return GpjShellBridge.transceive(data);
    }
}
