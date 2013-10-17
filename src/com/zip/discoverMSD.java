package com.zip;

import java.util.Random;
import com.iso.isoComm;
import com.tlv.TLVObjectSet;


public class discoverMSD {
	
	//express pay AID
	public static byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x24, 0x10, 0x10 };

	public class tracks
	{
		public byte[] track1;
		public byte[] track2;
	}
	
	private byte[] hex_to_ascii(byte[] hex, short offset, short leng)
	{
	  short i;
	  byte nib;
	  byte[] data = new byte[leng*2];
	  for(i=0;i<leng*2;i++)
	  {
	    if((i&0x01) == 0x01) nib=(byte)(short)((hex[offset+(i/2)])&0x0F);
	    else nib=(byte)((short)((hex[offset+(i/2)])&0xFF)>>4);
	    if(nib<0x0A) data[i]=(byte)(nib+0x30);
	    else data[i]=(byte)(nib+0x37);
	  }
	  return data;
	}

	private byte[] select()
	{
		//select Zip APDU
		byte[] data = new byte[AID.length + 6];  //header=5, footer=1
		data[0] = 0x00;
		data[1] = (byte)0xA4;
		data[2] = 0x04;
		data[3] = 0x00;
		data[4] = (byte) AID.length;
		for(byte i=0;i<AID.length;i++)
		{
			data[5+i] = AID[i];
		}
		data[5+AID.length] = 0x00;

		return isoComm.transceive(data);
	}

	private byte[] GPO(byte[] PDOL)
	{
		//GPO APDU
		byte[] data = new byte[7+PDOL.length+1]; 
		data[0] = (byte)0x80;
		data[1] = (byte)0xA8;
		data[2] = 0x00;
		data[3] = 0x00;
		data[4] = (byte)(short)((PDOL.length+2)&0xff);
		data[5] = (byte)0x83;
		data[6] = (byte)(short)(PDOL.length&0xff);
		for(short i=0;i<PDOL.length;i++)
		{
			data[7+i]=PDOL[i];
		}
		data[7+PDOL.length] = 0x00;
		return isoComm.transceive(data);
	}
	
	private byte[] readRecord()
	{
		//read record APDU
		byte[] data = new byte[5]; 
		data[0] = 0x00;
		data[1] = (byte)0xB2;
		data[2] = 0x01;
		data[3] = 0x0C;
		data[4] = 0x00;
		return isoComm.transceive(data);
	}

	private byte[] getTLVData(byte[] tag, TLVObjectSet TLVSet, byte[] data)
	{
		com.tlv.TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)tag.length);
		byte[] retData;
		if(TLVMsg==null)
		{
			retData = new byte[0];
		}
		else
		{
			retData = new byte[TLVMsg.leng];
			for(short i=0; i<TLVMsg.leng; i++)
			{
				retData[i] = data[TLVMsg.offset+i];
			}
		}
		return retData;
	}

	public tracks readTracks()
	{
		byte[] DCVV_TAG = new byte[2];
		DCVV_TAG[0] = (byte)0x9F;
		DCVV_TAG[1] = (byte)0x80;
		short PDOL_len;
		//select AID
		byte[] data = select();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		TLVObjectSet TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		byte[] tag = new byte[2];
		tag[0] = 0x6F; //FCI template
		com.tlv.TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0) 
		{
			TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
			byte[] tag1 = new byte[1];
			tag1[0] = (byte)0x84; //DF Name
			byte[] DF_NAME = getTLVData(tag1,TLVSet,data);
			if(DF_NAME.length!=AID.length)
				return null;
			for(short i=0;i<DF_NAME.length;i++)
				if(DF_NAME[i]!=AID[i])
					return null;  //DFNAME doesn't match command select
			tag[0] = (byte)0xA5; //FCI proprietary template
			TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
			if(TLVMsg!=null && TLVMsg.leng>0)
			{
				TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
				tag[0] = (byte)0x9F; //PDOL data
				tag[1] = (byte)0x38; //PDOL data
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
				if(TLVMsg!=null && TLVMsg.leng>0)
				{
					if((data[TLVMsg.offset]&0xff)!=0x9f || (data[TLVMsg.offset+1]&0xff)!=0x37 || data[TLVMsg.offset+2]<1 || data[TLVMsg.offset+2]>4 || TLVMsg.leng!=3)
					    return null;  //PDOL data incorrect
					PDOL_len = data[TLVMsg.offset+2];
				}
				else
					return null;
				tag[0] = (byte)0xBF; //FCI
				tag[1] = (byte)0x0C; //FCI
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
				if(TLVMsg!=null && TLVMsg.leng>0)
				{
					TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
					tag[0] = (byte)0x9F; //RF Indicator Data
					tag[1] = (byte)0x7D; //RF Indicator Data
					TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
					if(TLVMsg!=null && TLVMsg.leng>0)
					{
						if(TLVMsg.leng!=2)
							return null;
						if(data[TLVMsg.offset]>1)
						{
							DCVV_TAG[0] = (byte)0x9F;
							DCVV_TAG[1] = 0x7E;
						}
							
					}
				}
			}
			else
				return null;
		}
		else
			return null;
		
		//GPO
		byte[] UN = new byte[4];
		Random generator = new Random();
		short r;
		while(true)
		{
			r = (short)(generator.nextInt()&0x00007FFF);
			UN[0]=(byte)((byte)((((r%10000)/1000)*16)&0xFF) +         (byte)(((r%1000)/100)&0xFF));
			UN[1]=(byte)((byte)((((r%100)/10)*16)&0xFF) +             (byte)(((r%10)/1)&0xFF));
			r = (short)(generator.nextInt()&0x00007FFF);
			UN[2]=(byte)((byte)((((r%10000)/1000)*16)&0xFF) +         (byte)(((r%1000)/100)&0xFF));
			UN[3]=(byte)((byte)((((r%100)/10)*16)&0xFF) +             (byte)(((r%10)/1)&0xFF));
			short i;
		    for(i=0;i<PDOL_len;i++)
	    		if(UN[i]==0x00 || UN[i]==0x01)
	    			break; //failed UN check
		    if(i==PDOL_len)
		    	break;  //satisfied UN check, jump out
		}
		byte[] UN_BCD = new byte[PDOL_len];
		for(short i=0;i<UN_BCD.length;i++)
			UN_BCD[i] = UN[i];
		data = GPO(UN_BCD);
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		byte[] rec;
		TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		tag[0] = (byte)0x80; //format 1
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0)
		{
			if(((TLVMsg.leng-2)%4)!=0)
				return null;
			if(TLVMsg.leng<2 || data[TLVMsg.offset]!=0x00 || data[TLVMsg.offset+1]!=0x00)
				return null;
			rec = new byte[TLVMsg.leng-2];
			for(short i=0;i<rec.length;i++)
			{
				rec[i]=data[TLVMsg.offset+2+i];
			}
		}
		else
		{
			tag[0] = (byte)0x77; //format 2
			TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
			if(TLVMsg!=null && TLVMsg.leng>0)
			{
				TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
				byte[] tag1 = new byte[1];
				tag1[0] = (byte)0x82;
				byte[] AIP = getTLVData(tag1,TLVSet,data);
				if(AIP.length!=2 || AIP[0]!=0x00 || AIP[1]!=0x00)
					return null;
				tag1[0] = (byte)0x94;
				rec = getTLVData(tag1,TLVSet,data);
				if((rec.length%4)!=0)
					return null;
			}
			else
				return null;
		}
		//discover card check
		if(rec.length!=4 || rec[0]!=0x08 || rec[1]!=0x01 || rec[2]!=0x01 || rec[3] !=0x00)
		    return null;  //DISCOVER err
		
		//read record
		data = readRecord();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		tag = new byte[2];
		tag[0] = 0x70; //message
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0) //message
		{
			TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
		}
		else
			return null;
		byte[] tag1 = new byte[1];
		tag1[0] = 0x57;
		byte[] T2 = getTLVData(tag1,TLVSet,data);
		if(T2.length==0)
			return null;
		T2 = hex_to_ascii(T2,(short)0,(short)T2.length);
		short T2_len=0;
		short i;
        for(i = 0; i<T2.length; i++) 
        {
          //sub the 'D' with '='
          if(T2[i]=='D' || T2[i]=='d') 
          {
     	      T2[i]='=';
          }
          //break at the end of the track
          if(T2[i]=='F' || T2[i]=='f')
            break;
        }
        T2_len = i;
		if(T2_len<1)
			return null;
		tag1[0] = 0x56;
		byte[] T1 = getTLVData(tag1,TLVSet,data);
		if(T1.length==0)
			return null;

		byte[] DCVV = getTLVData(DCVV_TAG,TLVSet,data);
		DCVV = hex_to_ascii(DCVV,(short)0,(short)DCVV.length);
		UN_BCD = hex_to_ascii(UN_BCD,(short)0,(short)UN_BCD.length);
		//sub
		if(DCVV.length>5)
		{
			if(T1.length<63 + UN_BCD.length +1 || T2_len<35 + UN_BCD.length+1)
				return null;
		  	//insert DCVV
		    for(i=0;i<3;i++)
		    {
		    	T1[57+i] = DCVV[i*2+1];
		    	T2[29+i] = DCVV[i*2+1];
		    }
		    for(i=0;i<UN_BCD.length;i++)
		    {
		    	T1[63+i]=UN_BCD[i];
		    	T2[35+i]=UN_BCD[i];
		    }
		}
		tracks tracks = new tracks();
		tracks.track1 = new byte[1+T1.length+1+1];
		short index=0;
		tracks.track1[index++] = '%';
		for(i=0;i<T1.length;i++) 
			tracks.track1[index++] = T1[i];
		tracks.track1[index++] = '?';
	    byte LRC = 0x00;
	    for(short j=0;j<tracks.track1.length-1;j++)
	    {
	    	LRC = (byte)((LRC+tracks.track1[j])&0xFF);	
	    }
	    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
		tracks.track1[tracks.track1.length-1]=LRC;

		tracks.track2 = new byte[1+T2_len+1+1];
		index=0;
		tracks.track2[index++] = ';';
		for(i=0;i<T2_len;i++) 
			tracks.track2[index++] = T2[i];
		tracks.track2[index++] = '?';
	    LRC = 0x00;
	    for(short j=0;j<tracks.track2.length-1;j++)
	    {
	    	LRC = (byte)((LRC+tracks.track2[j])&0xFF);	
	    }
	    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
		tracks.track2[tracks.track2.length-1]=LRC;

		return tracks;
	}
}
