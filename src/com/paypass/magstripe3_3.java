package com.paypass;

import com.iso.isoComm;
import com.tlv.TLVObjectSet;

import java.util.Random;

public class magstripe3_3 {
	//paypass AID
	public static byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10 };

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

	//takes 2 bytes hex and replaces with 3 bytes dec
	private byte[] hex_to_dec(byte[] hex)
	{
		byte[] data=new byte[3];
		long num = (short)(hex[0]&0xFF)*256 + (short)(hex[1]&0xFF);
		data[0]=(byte)((byte)((((num%1000000)/100000)*16)&0xFF) +     (byte)(((num%100000)/10000)&0xFF));
		data[1]=(byte)((byte)((((num%10000)/1000)*16)&0xFF) +         (byte)(((num%1000)/100)&0xFF));
		data[2]=(byte)((byte)((((num%100)/10)*16)&0xFF) +             (byte)(((num%10)/1)&0xFF));
		return data;
	}

	void insert_bitmap(byte[] buf, short buf_len, byte[] bitmap, short bitmap_len, byte[] data, short data_len)
	{
		short i;
		short j;
		short data_index = (short)(data_len - 1);
			    	
		for(i=bitmap_len;i>0;i--)
		{
			for(j=0;j<8;j++) 
			{
				if((((short)(bitmap[i-1]&0xff)>>j)&0x01) == 0x01)
				{
				 if((buf_len - 1 - 8*(bitmap_len-i) - j)>=buf_len) break;
				 if(data_index>=data_len) break;
				 buf[buf_len - 1 - 8*(bitmap_len-i) - j] = data[data_index--];
				}
			}    
		}
	}
	
	private byte[] select()
	{
		//select PayPass APDU
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

	private byte[] GPO()
	{
		//GPO APDU
		byte[] data = new byte[8]; 
		data[0] = (byte)0x80;
		data[1] = (byte)0xA8;
		data[2] = 0x00;
		data[3] = 0x00;
		data[4] = 0x02;
		data[5] = (byte)0x83;
		data[6] = 0x00;
		data[7] = 0x00;
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

	private byte[] CCC(byte[] UN)
	{
		//compute cryptographic checksum APDU
		byte[] data = new byte[10]; 
		data[0] = (byte)0x80;
		data[1] = 0x2A;
		data[2] = (byte)0x8E;
		data[3] = (byte)0x80;
		data[4] = (byte)0x04;
		for(short i=0;i<UN.length;i++)
		{
			data[5+i] = UN[i];
		}
		data[9] = 0x00;
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
		
		//select AID
		byte[] data = select();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		//GPO
		data = GPO();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;
		//read record
		data = readRecord();
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;

		TLVObjectSet TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		byte[] tag = new byte[2];
		tag[0] = 0x70; //message
		com.tlv.TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0) //message
		{
			TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
		}
		else
			return null;
		
		//NATCT2
		tag[0] = (byte)0x9f;
		tag[1] = (byte)0x67;
		byte[] NATCT2 = getTLVData(tag,TLVSet,data);
		if(NATCT2.length!=1)
			return null;
		
		//T2
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x6B;
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
		if(TLVMsg!=null && TLVMsg.leng==0)
			return null;
		byte[] T2 = hex_to_ascii(data,TLVMsg.offset,TLVMsg.leng);
		short i;
	    for(i = 0; i<T2.length; i++) 
	    {
	    	//sub the 'D' with '='
	        if(T2[i]=='D' || T2[i]=='d') 
	        	T2[i]='=';
	        //break at the end of the track
	        if(T2[i]=='F' || T2[i]=='f')
	        	break;
	    }
		short T2_len = i;

		//PUNATCT2
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x66;
		byte[] PUNATCT2 = getTLVData(tag,TLVSet,data);
		if(PUNATCT2.length!=2)
			return null;

		//PCVC3T2
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x65;
		byte[] PCVC3T2 = getTLVData(tag,TLVSet,data);
		if(PCVC3T2.length!=2)
			return null;

		//NATCT1
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x64;
		byte[] NATCT1 = getTLVData(tag,TLVSet,data);

		//PUNATCT1
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x63;
		byte[] PUNATCT1 = getTLVData(tag,TLVSet,data);

		//PCVC3T1
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x62;
		byte[] PCVC3T1 = getTLVData(tag,TLVSet,data);

		//T1
		byte[] tag1 = {0x56};
		byte[] T1 = getTLVData(tag1,TLVSet,data);

		//NUN
		byte NUN=0;
		for(i=2;i>0;i--)
		{
			for(byte j=0;j<8;j++) if(((PUNATCT2[i-1]>>j)&0x01) == 0x01) NUN++;
		}
		if((short)(NUN-NATCT2[0])<0)
			return null;
		NUN-=NATCT2[0];

		//CCC
		byte[] UN = new byte[4];
		Random generator = new Random();
		short r = (short)(generator.nextInt()&0x00007FFF);
		UN[0]=(byte)(((byte)((((r%10000)/1000)*16)&0xFF) + (byte)(((r%1000)/100)&0xFF))&0xFF);
		UN[1]=(byte)(((byte)((((r%100)/10)*16)&0xFF) + (byte)(((r%10)/1)&0xFF))&0xFF);
		r = (short)(generator.nextInt()&0x00007FFF);
		UN[2]=(byte)(((byte)((((r%10000)/1000)*16)&0xFF) + (byte)(((r%1000)/100)&0xFF))&0xFF);
		UN[3]=(byte)(((byte)((((r%100)/10)*16)&0xFF) + (byte)(((r%10)/1)&0xFF))&0xFF);
		for(i=0;i<8-NUN;i++) //now mask NUN nibbles into UN
		{
		 	if(i%2==0) UN[i/2]&=0x0F;
		  	else UN[i/2]&=0xF0;
		}
		byte[] UN_ascii = hex_to_ascii(UN,(short)0,(short)UN.length);  //save UN for later
		data = CCC(UN);
		if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
			return null;

		TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		tag[0] = 0x77; //message
		TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0) //message
		{
			TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
		}
		else
			return null;

		//CVC3T2
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x61;
		byte[] CVC3T2 = getTLVData(tag,TLVSet,data);
		if(CVC3T2.length!=2)
			return null;
		CVC3T2 = hex_to_dec(CVC3T2);
		
		//CVC3T1
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x60;
		byte[] CVC3T1 = getTLVData(tag,TLVSet,data);
		if(CVC3T1.length!=2)
			return null;
		CVC3T1 = hex_to_dec(CVC3T1);

		//ATC
		tag[0] = (byte)0x9F;
		tag[1] = (byte)0x36;
		byte[] ATC = getTLVData(tag,TLVSet,data);
		if(ATC.length!=2)
			return null;
		ATC = hex_to_dec(ATC);

		//sub back into T2
		if(T2_len>0)
		{
		    byte[] ATCT2 = hex_to_ascii(ATC,(short)0,(short)3);
		    byte[] UNATC = new byte[NATCT2[0]+NUN];
		    for(i=0;i<NATCT2[0];i++) 
		    {
		    	UNATC[i] = ATCT2[ATCT2.length-NATCT2[0]+i];
		    }
		    for(i=0;i<NUN;i++) 
		    {
		    	UNATC[i+NATCT2[0]] = UN_ascii[UN_ascii.length-NUN+i];
		    }
		    
		    //now sub the data into the T2 string
		    insert_bitmap(T2, (short)T2_len, PUNATCT2, (short)2, UNATC, (short)UNATC.length);
		    CVC3T2 = hex_to_ascii(CVC3T2,(short)0,(short)3);
		    insert_bitmap(T2, (short)T2_len, PCVC3T2, (short)2, CVC3T2, (short)CVC3T2.length);
		    //sub in NUN
		    T2[T2_len-1]=(byte)(NUN+0x30);  //ascii value of NUN
		}
		else
			return null;
		tracks tracks = new tracks();
	    tracks.track2 = new byte[T2_len+3];
	    tracks.track2[0]=';';
	    byte LRC = 0x00;
	    LRC = (byte)((LRC+';')&0xFF);
	    for(i=0;i<T2_len;i++)
	    {
	    	tracks.track2[i+1] = T2[i];
		    LRC = (byte)((LRC+T2[i])&0xFF);
	    }
	    tracks.track2[i+1] = '?';
	    LRC = (byte)((LRC+'?')&0xFF);
	    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
	    tracks.track2[i+2] = LRC;

		//Now Track 1
		if(T1.length>0)
		{
			//make sure we have all madatory data
		    if(NATCT1.length!=1)
				return null;
			if(PUNATCT1.length!=6)
				return null;
			if(PCVC3T1.length!=6)
				return null;
		    byte[] ATCT1 = hex_to_ascii(ATC,(short)0,(short)3);
		    byte[] UNATC = new byte[NATCT1[0]+NUN];
		    for(i=0;i<NATCT1[0];i++) 
		    {
		    	UNATC[i] = ATCT1[ATCT1.length-NATCT1[0]+i];
		    }
		    for(i=0;i<NUN;i++) 
		    {
		    	UNATC[i+NATCT1[0]] = UN_ascii[UN_ascii.length-NUN+i];
		    }
		    //now sub the data into the T1 string
		    insert_bitmap(T1, (short)T1.length, PUNATCT1, (short)6, UNATC, (short)UNATC.length);
		    CVC3T1 = hex_to_ascii(CVC3T1,(short)0,(short)3);
		    insert_bitmap(T1, (short)T1.length, PCVC3T1, (short)6, CVC3T1, (short)CVC3T1.length);
		    //sub in NUN
		    T1[T1.length-1]=(byte)(NUN+0x30);  //ascii value of NUN
		    tracks.track1 = new byte[T1.length+3];
		    tracks.track1[0]='%';
		    LRC = 0x00;
		    LRC = (byte)((LRC+'%')&0xFF);
		    for(i=0;i<T1.length;i++)
		    {
		    	tracks.track1[i+1] = T1[i];
			    LRC = (byte)((LRC+T1[i])&0xFF);
		    }
		    tracks.track1[i+1] = '?';
		    LRC = (byte)((LRC+'?')&0xFF);
		    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
		    tracks.track1[i+2] = LRC;
		}

		return tracks;
	}
}
