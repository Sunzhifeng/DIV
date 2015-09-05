package fileOperation;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.io.IOUtils;

import MHT.MHTPADD_01;
import tool.StdOut;

/**
 * ��HDFS�ϲ����ļ�
 * @author MichaelSun
 * @version 1
 * @date 2014.11.17
 */
public class HDFSFileOperation {	
	public static String hdfsPath="hdfs://master:9000/user/sunzhifeng/input/";
	public static final int K=1024;		//KB
	public static Element[][] sectors;

	/**
	 * ��ȡ�ļ�����ս�鲢ӳ������е�Ԫ��
	 * @param fileName  �ļ���
	 * @param c         ��ս�Ŀ���
	 * @param blockSize �ļ����С 
	 * @param blockNum 	���ݿ�ı��1-n֮��
	 * @throws IOException
	 */
	public Element[] readfileofCBlocks(String fileName,int c,int blockSize,int []blockNum,Field r) throws IOException{
		Configuration conf = new Configuration();
		//���һ����HDFS�ӿڵ�FileSystem����
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		byte[] blockBuff=new byte[blockSize*K];		
		Element [] pdata=new Element[c];

		//�Կ�ı����������
		Arrays.sort(blockNum);		 
		FSDataInputStream in=hdfs.open(file);

		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩
		for(int i=0;i<c;i++){
			in.seek((blockNum[i]-1)*blockSize*K);
			in.read(blockBuff);
			//�����ݽ���������
			pdata[i]=r.newElementFromBytes(blockBuff);
			System.out.println("��"+blockNum[i]+"���ֵ��"+new String(Hex.encodeHex(blockBuff)));
			System.out.println("��"+blockNum[i]+"�����ֵ��"+new String(Hex.encodeHex(pdata[i].toBytes())));

		}		
		in.close();

		return pdata;
	}

	/**
	 * ���ļ����鴦���õ���Ӧ������Ԫ�ؼ���
	 * @param fileName �ļ���
	 * @param blockSize �߼��ֿ��С
	 * @param r 		������
	 * @return          ���п�ӳ������Ԫ�ؼ���
	 * @throws IOException
	 */
	public Element[] preProcessFile(String fileName,int blockSize,Field r) throws IOException{
		Configuration conf = new Configuration();
		//���һ����HDFS�ӿڵ�FileSystem����
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		//FileStatus�洢�ļ���Ŀ¼Ԫ��Ϣ
		FileStatus fstatus=hdfs.getFileStatus(file);	 		
		//����ļ�����
		long fileSize=fstatus.getLen();
		int fileBlocks=(int)fileSize/(blockSize*K);
		long remain=fileSize%(blockSize*K);		
		fileBlocks=remain>0?fileBlocks+1:fileBlocks;
		//StdOut.println("�ļ���С:"+fileSize+"B ���ļ�����:"+fileBlocks);

		byte[] blockBuff=new byte[blockSize*K];		
		Element [] pdata=new Element[fileBlocks];			 
		FSDataInputStream in=hdfs.open(file);		
		int c;
		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩
		//StdOut.println("blockData->Zp��");
		for(int i=0;i<fileBlocks-1;i++){//����ǰfileBlocks-1��			
			in.read(blockBuff);			
			pdata[i]=r.newElementFromHash(blockBuff,0,blockBuff.length);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
			//pdata[i]=r.newElementFromBytes(blockBuff);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
		//	System.out.print((i+1)+"block ");
		}
		c=in.read(blockBuff);
		in.close();
		if(c==blockSize*K){
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);
			//pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);
			System.out.print((fileBlocks)+"block ");
		}else{//���һ����ܲ����������⴦��,����0���
			for(int k=c;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);			
			//pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);
			System.out.print((fileBlocks)+"block ");
			System.out.print("�����С��"+c);
		}
		StdOut.println();
		return pdata;
	}
	/**
	 * ���ļ�����Ԥ�������ֿ�ͷֶ�
	 * @param fileName	�ļ���
	 * @param blockSize	���С
	 * @param s			ÿ��Ķ���
	 * @param sectorSize	�δ�С
	 * @param r			��������
	 * @return			n���ļ������Ԫ��
	 * @throws IOException
	 */
	public Element[] preProcessFile(String fileName,int blockSize,int s,int sectorSize,Field r) throws IOException{
		Configuration conf = new Configuration();
		//���һ����HDFS�ӿڵ�FileSystem����
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		//FileStatus�洢�ļ���Ŀ¼Ԫ��Ϣ
		FileStatus fstatus=hdfs.getFileStatus(file);
		
		//����ļ�����	   
		long fileSize=fstatus.getLen();
		int fileBlocks=(int)fileSize/(blockSize*K);
		long remain=fileSize%(blockSize*K);		
		fileBlocks=remain>0?fileBlocks+1:fileBlocks;
		//StdOut.println("�ļ���С:"+fileSize+"B ���ļ�����:"+fileBlocks+",�ļ����С��"+blockSize+"K"+",����"+s+"���δ�С��"+sectorSize);
		//int fileBlocks=getBlocksOfFile(hdfs, file, blockSize);

		byte[] blockBuff=new byte[blockSize*K];		
		Element [] pdata=new Element[fileBlocks];	
		//sectors=new HashMap<Integer,Object>(fileBlocks);//������п�ķֶ���Ϣ��
		sectors=new Element[fileBlocks][s];
		FSDataInputStream in=hdfs.open(file);		

		//������Բ�ȡ���̲߳��д���������Ԫ�ء���mapreduce��˼�룩
	//	StdOut.println("blockData->Zp,Sector��");
		for(int i=0;i<fileBlocks-1;i++){//����ǰfileBlocks-1��			
			in.read(blockBuff,0,blockSize*K);			
			pdata[i]=r.newElementFromHash(blockBuff,0,blockBuff.length);//�����ݽ���������.����ʹ��hash���ٶ���������Ҳ������newElementFromBytes
			sectors[i]=preProcessBlock(s, blockBuff, sectorSize, r);//��i��ķֶ���Ϣ�ӵ�sectors��
		//	System.out.print((i+1)+"block ");
		}
		int c=in.read(blockBuff);
		in.close();
		if(c==blockSize*K){//���һ�����⴦��
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);
			sectors[fileBlocks-1]=preProcessBlock(s, blockBuff, sectorSize, r);
		//	StdOut.println((fileBlocks)+"block ");
		//	StdOut.println("�����С��"+c);
		}else{//���һ����ܲ����������⴦��,����0���
			for(int k=c;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);	
			sectors[fileBlocks-1]=preProcessBlock(s, blockBuff, sectorSize, r);
			//StdOut.println((fileBlocks)+"block ");
			//StdOut.println("�����С��"+c);
		}
		//StdOut.println();
		return pdata;
	}
	/**
	 * �Կ���зֶδ���
	 * @param s 		����
	 * @param blockData ������
	 * @param sectorSize �δ�С
	 * @param r 		������
	 * @return 			s����Ԫ��	
	 */
	public Element[] preProcessBlock(int s,byte[] blockData,int sectorSize,Field r){

		Element[] sectorNums=new Element[s];
		for(int i=0;i<s;i++){
			sectorNums[i]=r.newElementFromHash(blockData,i*sectorSize,sectorSize);
		}
		return sectorNums;
	}

	/**
	 * ����ļ��Ŀ���
	 * @param fileName �ļ���
	 * @param blockSize ���С
	 * @return �ļ�����
	 * @throws IOException
	 */
	public int getBlocksOfFile(String fileName,int blockSize) throws IOException{
		Configuration conf = new Configuration();		
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		//FileStatus�洢�ļ���Ŀ¼Ԫ��Ϣ
		FileStatus fstatus=hdfs.getFileStatus(file);	 		
		//����ļ�����
		long fileSize=fstatus.getLen();
		int fileBlocks=(int)fileSize/(blockSize*K);
		long remain=fileSize%(blockSize*K);		
		//System.out.println("�ļ���С"+fileSize+" ���ļ�����"+fileBlocks);
		return remain>0?fileBlocks+1:fileBlocks;
	}



	
	

}