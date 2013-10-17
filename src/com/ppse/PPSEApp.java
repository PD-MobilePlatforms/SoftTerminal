package com.ppse;
import com.expresspay.*;
import com.iso.*;
import com.paymentreader.*;
import com.paypass.*;
import com.tlv.*;
import com.visacontactless.*;
import com.zip.*;

public class PPSEApp {

	private byte findAID(byte[] data, short dataOffset)
	{
		//check for paypass match
		if(readCard.arrayCompare(data, dataOffset, magstripe3_3.AID, (short)0, (short)magstripe3_3.AID.length))
		{
			return readCard.PayPass;
		}
		//check for visa match
		if(readCard.arrayCompare(data, dataOffset, visaMSD.AID, (short)0, (short)visaMSD.AID.length))
		{
			return readCard.VisaContactless;
		}
		//check for amex match
		if(readCard.arrayCompare(data, dataOffset, MSD.AID, (short)0, (short)MSD.AID.length))
		{
			return readCard.ExpressPay;
		}
		//check for discover match
		if(readCard.arrayCompare(data, dataOffset, discoverMSD.AID, (short)0, (short)discoverMSD.AID.length))
		{
			return readCard.Zip;
		}
		
		return 0;
	}
	
	public byte getApp()
	{
		byte result = 0;
		//select PPSE APDU
		byte[] data = {0x00, (byte) 0xA4, 0x04, 0x00, 0x0E, 0x32, 
				       0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 
				       0x44, 0x44, 0x46, 0x30, 0x31, 0x00};
		data = isoComm.transceive(data);
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
		{
			result = readCard.tryAll;
			return result;
		}
		TLVObjectSet TLVSet;
		com.tlv.TLVObjectSet.TLVObject TLVMsg;
		boolean foundAID=false;
		if(data!=null)
		{
			TLVSet = new TLVObjectSet();
			TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
			byte[] tag = new byte[2];
			tag[0] = 0x6F; //FCI Template
			TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
			if(TLVMsg.leng>0) //found FCI Template
			{
				TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
				tag[0] = (byte)0xA5; //FCI Proprietary Template
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
				if(TLVMsg.leng>0) //found FCI Proprietary Template
				{
					TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
					tag[0] = (byte)0xBF; //FCI Issuer Discretionary Data
					tag[1] = (byte)0x0C; //FCI Issuer Discretionary Data
					TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
					if(TLVMsg.leng>0) //found FCI Issuer Discretionary Data
					{
						TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
						tag[0] = (byte)0x61; //Directory Entry
						TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
						if(TLVMsg.leng>0) //found Directory Entry
						{
							TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
							tag[0] = (byte)0x4F; //ADF
							TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
							if(TLVMsg.leng>0) //found ADF
							{
								foundAID = true;
								//see if the AID matches any of the protocols our reader supports
							}						
						}						
					}					
				}
			}
			if(foundAID)
			{
				result = findAID(data,TLVMsg.offset);
			}
			else
			{
				//PPSE failed to find an AID
				//cycle through all of them
				result = readCard.tryAll;
			}
		}
		
		return result;
	}
}
