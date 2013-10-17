package com.visacontactless;

import com.iso.isoComm;
import com.tlv.TLVObjectSet;

public class visaMSD {

	//visa AID
	public static byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10 };

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

	private byte[] readRecord(byte P1, byte P2)
	{
		//select visa APDU
		byte[] data = new byte[5];  //header=5
		data[0] = 0x00;
		data[1] = (byte)0xB2;
		data[2] = P1;
		data[3] = P2;
		data[4] = 0x00;

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

	private byte[] getTLVData(byte[] tag, TLVObjectSet TLVSet, byte[] data)
	{
		TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)tag.length);
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
		TLVObjectSet TLVSet = new TLVObjectSet();
		TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
		byte[] tag = new byte[2];
		tag[0] = 0x6F; //FCI template
		TLVObjectSet.TLVObject TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
		if(TLVMsg!=null && TLVMsg.leng>0) 
		{
			TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
			tag[0] = (byte)0xA5; //FCI proprietary template
			TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
			if(TLVMsg!=null && TLVMsg.leng>0)
			{
				TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
				tag[0] = (byte)0x9F; //PDOL data
				tag[1] = (byte)0x38; //PDOL data
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)2);
				if(TLVMsg.leng<1) 
					return null;
			}
			else
				return null;
		}
		else
			return null;
		short offset = TLVMsg.offset;
		short msgLen = TLVMsg.leng;
		byte[] PDOL = new byte[0];
		byte validation=0;
		for(short i=offset;i<msgLen+offset;)
		{
			if(TLVMsg.getTLVObject(data, i, false))
			{
				if((short)(TLVMsg.offset-i)<1)
					break;
				i=TLVMsg.offset;
				byte[] tmp = new byte[PDOL.length + TLVMsg.leng];
				short j;
				for(j=0;j<PDOL.length;j++)
				{
					tmp[j]=PDOL[j];
				}
				PDOL=tmp;
				if(TLVMsg.tagLeng==2 && 
						(byte)data[TLVMsg.tagOffset] == (byte)0x9F &&
						(byte)data[TLVMsg.tagOffset+1] == (byte)0x66)
				{
					validation=1;
					for(short k=0; k<TLVMsg.leng;k++)
					{
						if(k==0)
							PDOL[j+k] = (byte)0x80;
						else
							PDOL[j+k] = 0x00;
					}
				}
				else
				{
					for(short k=0; k<TLVMsg.leng;k++)
					{
						PDOL[j+k] = 0x00;
					}
				}
			}
			else
				break;
		}
		//GPO
		data = GPO(PDOL);
		if(validation==0 || data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
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
				byte[] tag1 = {(byte)0x94};
				rec = getTLVData(tag1,TLVSet,data);
				if((rec.length%4)!=0)
					return null;
			}
			else
				return null;
		}
		short i=0;
		byte[] T2 = new byte[0];
		short T2_len=0;
		short PAN_len=0;
		byte[] T1DD = new byte[0];
		byte[] NAME = new byte[0];
		byte[] EXP = new byte[0];
		byte[] SC = new byte[0];
		while(i<rec.length)
		{
			if(((short)(rec[i+2]&0xff)-(short)(rec[i+1]&0xff))<0)
				return null;
			for(short j=0;j<((short)(rec[i+2]&0xff)-(short)(rec[i+1]&0xff)+1);j++)
			{
				//read record
				data = readRecord((byte)(((short)(rec[i+1]&0xff) + j)&0xff),(byte)((0x04|rec[i])&0xff));
				if(data==null || data.length<2 || data[data.length-2]!=(byte)0x90 || data[data.length-1]!=(byte)0x00)
					return null;
				TLVSet = new TLVObjectSet();
				TLVSet.getTLVObjectSet(data,(short)0,(short)(data.length-2));
				tag[0] = (byte)0x70; //MSG
				TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
				if(TLVMsg!=null && TLVMsg.leng>0)
				{
					TLVSet.getTLVObjectSet(data,(short)TLVMsg.offset,(short)TLVMsg.leng);
					//get TAG data
					tag[0] = (byte)0x57; //T2
					TLVMsg = TLVSet.getTLVObject(data, tag, (short)0, (short)1);
					if(TLVMsg!=null && TLVMsg.leng>0)
					{
						T2 = hex_to_ascii(data,TLVMsg.offset,TLVMsg.leng);
						short k;
						for(k=0;k<T2.length;k++)
						{
							if(T2[k]=='D' || T2[k]=='d')
							{
								PAN_len=k;
								T2[k]='=';
								if((T2.length-k+1)>7)
								{
									if(EXP.length==0)
									{
										EXP = new byte[4];
										EXP[0]=T2[k+1];
										EXP[1]=T2[k+2];
										EXP[2]=T2[k+3];
										EXP[3]=T2[k+4];
									}
									if(SC.length==0)
									{
										SC = new byte[4];
										SC[0]=T2[k+5];
										SC[1]=T2[k+6];
										SC[2]=T2[k+7];
										SC[3]=T2[k+8];
									}
								}
							}
							if(T2[k]=='F' || T2[k]=='f')
							{
								break;
							}
						}
						T2_len = k;
					}
					tag[0]=(byte)0x9F; //T1 DD
					tag[1]=(byte)0x1F; //T1 DD
					byte tmp[] = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						T1DD = tmp;
					tag[0]=(byte)0x5F; //T1 NAME
					tag[1]=(byte)0x20; //T1 NAME
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						NAME = tmp;
					tag[0]=(byte)0x5F; //T1 EXP
					tag[1]=(byte)0x24; //T1 EXP
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						EXP = hex_to_ascii(tmp,(short)0,(short)2);
					tag[0]=(byte)0x5F; //T1 SC
					tag[1]=(byte)0x30; //T1 SC
					tmp = getTLVData(tag,TLVSet,data);
					if(tmp.length>0)
						SC = hex_to_ascii(tmp,(short)0,(short)2);
				}
				else
					return null;
			}
			i+=4;
		}
		if(T2_len==0 || PAN_len==0)
			return null;
		tracks tracks = new tracks();
		//now build track strings
		if(NAME.length>0 && T1DD.length>0)
		{
			short T1_len = (short)(2 + PAN_len + 1 + NAME.length + 1 + EXP.length + SC.length + T1DD.length + 1 + 1);
			if(EXP.length ==0)
				T1_len++;
			if(SC.length ==0)
				T1_len++;
			tracks.track1 = new byte[T1_len];
			i=0;
			tracks.track1[i++] = '%';
			tracks.track1[i++] = 'B';
			for(short j=0;j<PAN_len;j++)
			{
				tracks.track1[i++]=T2[j];
			}
			tracks.track1[i++] = '^';
			for(short j=0;j<NAME.length;j++)
			{
				tracks.track1[i++]=NAME[j];
			}
			tracks.track1[i++] = '^';
			for(short j=0;j<EXP.length;j++)
			{
				tracks.track1[i++]=EXP[j];
			}
			if(EXP.length==0)
			{
				tracks.track1[i++] = 'w';
			}
			for(short j=0;j<SC.length;j++)
			{
				tracks.track1[i++]=SC[j];
			}
			if(SC.length==0)
			{
				tracks.track1[i++] = 'w';
			}
			for(short j=0;j<T1DD.length;j++)
			{
				tracks.track1[i++]=T1DD[j];
			}
			tracks.track1[i++] = '?';
		    byte LRC = 0x00;
		    for(short j=0;j<i;j++)
		    {
		    	LRC = (byte)((LRC+tracks.track1[j])&0xFF);	
		    }
		    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
			tracks.track1[i]=LRC;
		}
		if(T2_len>0)
		{
			tracks.track2 = new byte[1 + T2_len + 1 + 1];
			i=0;
			tracks.track2[i++] = ';';
			for(short j=0;j<T2_len;j++)
			{
				tracks.track2[i++]=T2[j];
			}
			tracks.track2[i++] = '?';
		    byte LRC = 0x00;
		    for(short j=0;j<i;j++)
		    {
		    	LRC = (byte)((LRC+tracks.track2[j])&0xFF);	
		    }
		    LRC = (byte)(((LRC^0xFF)+1)&0xFF);
			tracks.track2[i]=LRC;
		}
		return tracks;
	}
}
