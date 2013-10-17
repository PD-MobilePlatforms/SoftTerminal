package com.paymentreader;

import com.expresspay.*;
import com.paypass.*;
import com.ppse.*;
import com.visacontactless.*;
import com.zip.*;

public class readCard {

	static public byte PayPass = 0x01;
	static public byte VisaContactless = 0x02;
	static public byte ExpressPay = 0x03;
	static public byte Zip = 0x04;
	static public byte tryAll = (byte)0xFF;
	public byte cardType = 0;
	
	static public boolean arrayCompare(byte[] data0, short data0Offset, byte[] data1, short data1Offset, short compLen)
	{
		for (short i=0; i<compLen; i++)
		{
			if(data0.length<=(data0Offset+i))
				return false;
			if(data1.length<=(data1Offset+i))
				return false;
			if(data0[data0Offset+i] != data1[data1Offset+i])
				return false;
		}
		return true;
	}

	public String read()
	{
		byte[] track1 = null;
		byte[] track2 = null;
		PPSEApp ppse = new PPSEApp();
		byte app = ppse.getApp();
		
		if(app == tryAll)
		{
			//try PayPass
			if(track1==null && track2==null)
			{
				magstripe3_3 paypass = new magstripe3_3();
				magstripe3_3.tracks tracks = paypass.readTracks();
				if(tracks!=null)
				{
					track1 = tracks.track1;
					track2 = tracks.track2;
					cardType = PayPass;
				}
			}
			//try VisaContactless
			if(track1==null || track2==null)
			{
				visaMSD vc = new visaMSD();
				visaMSD.tracks tracks = vc.readTracks();
				if(tracks!=null)
				{
					track1 = tracks.track1;
					track2 = tracks.track2;
					cardType = VisaContactless;
				}
			}
			//try ExpressPay
			if(track1==null || track2==null)
			{
				MSD ep = new MSD();
				MSD.tracks tracks = ep.readTracks();
				if(tracks!=null)
				{
					track1 = tracks.track1;
					track2 = tracks.track2;
					cardType = ExpressPay;
				}
			}
			//try Zip
			if(track1==null || track2==null)
			{
				discoverMSD zip = new discoverMSD();
				discoverMSD.tracks tracks = zip.readTracks();
				if(tracks!=null)
				{
					track1 = tracks.track1;
					track2 = tracks.track2;
					cardType = Zip;
				}
			}
		}
		else if(app==PayPass)
		{
			magstripe3_3 paypass = new magstripe3_3();
			magstripe3_3.tracks tracks = paypass.readTracks();
			if(tracks!=null)
			{
				track1 = tracks.track1;
				track2 = tracks.track2;
				cardType = PayPass;
			}
		}
		else if(app==VisaContactless)
		{
			visaMSD vc = new visaMSD();
			visaMSD.tracks tracks = vc.readTracks();
			if(tracks!=null)
			{
				track1 = tracks.track1;
				track2 = tracks.track2;
				cardType = VisaContactless;
			}
		}
		else if(app==ExpressPay)
		{
			MSD ep = new MSD();
			MSD.tracks tracks = ep.readTracks();
			if(tracks!=null)
			{
				track1 = tracks.track1;
				track2 = tracks.track2;
				cardType = ExpressPay;
			}
		}
		else if(app==Zip)
		{
			discoverMSD zip = new discoverMSD();
			discoverMSD.tracks tracks = zip.readTracks();
			if(tracks!=null)
			{
				track1 = tracks.track1;
				track2 = tracks.track2;
				cardType = Zip;
			}
		}
		
		String trans = null;
		if(track1!=null || track2!=null)
			trans="";
		if(track1!=null)
		{
			for(short i=0;i<track1.length-1;i++) //don't include the LRC
			{
				trans+=(char)track1[i];
			}
		}
		if(track2!=null)
		{
			for(short i=0;i<track2.length-1;i++) //don't include the LRC
			{
				trans+=(char)track2[i];
			}
		}
		return trans;
	}
}
