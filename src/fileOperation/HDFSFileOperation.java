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
 * 从HDFS上操作文件
 * @author MichaelSun
 * @version 1
 * @date 2014.11.17
 */
public class HDFSFileOperation {	
	public static String hdfsPath="hdfs://master:9000/user/sunzhifeng/input/";
	public static final int K=1024;		//KB
	public static Element[][] sectors;

	/**
	 * 读取文件的挑战块并映射成域中的元素
	 * @param fileName  文件名
	 * @param c         挑战的块数
	 * @param blockSize 文件块大小 
	 * @param blockNum 	数据块的编号1-n之间
	 * @throws IOException
	 */
	public Element[] readfileofCBlocks(String fileName,int c,int blockSize,int []blockNum,Field r) throws IOException{
		Configuration conf = new Configuration();
		//获得一个与HDFS接口的FileSystem对象
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		byte[] blockBuff=new byte[blockSize*K];		
		Element [] pdata=new Element[c];

		//对块的编号升序排列
		Arrays.sort(blockNum);		 
		FSDataInputStream in=hdfs.open(file);

		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）
		for(int i=0;i<c;i++){
			in.seek((blockNum[i]-1)*blockSize*K);
			in.read(blockBuff);
			//对数据进行域运算
			pdata[i]=r.newElementFromBytes(blockBuff);
			System.out.println("第"+blockNum[i]+"块的值："+new String(Hex.encodeHex(blockBuff)));
			System.out.println("第"+blockNum[i]+"块的域值："+new String(Hex.encodeHex(pdata[i].toBytes())));

		}		
		in.close();

		return pdata;
	}

	/**
	 * 对文件按块处理，得到对应的域中元素集合
	 * @param fileName 文件名
	 * @param blockSize 逻辑分块大小
	 * @param r 		域运算
	 * @return          所有块映射后的域元素集合
	 * @throws IOException
	 */
	public Element[] preProcessFile(String fileName,int blockSize,Field r) throws IOException{
		Configuration conf = new Configuration();
		//获得一个与HDFS接口的FileSystem对象
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		//FileStatus存储文件和目录元信息
		FileStatus fstatus=hdfs.getFileStatus(file);	 		
		//获得文件块数
		long fileSize=fstatus.getLen();
		int fileBlocks=(int)fileSize/(blockSize*K);
		long remain=fileSize%(blockSize*K);		
		fileBlocks=remain>0?fileBlocks+1:fileBlocks;
		//StdOut.println("文件大小:"+fileSize+"B ，文件块数:"+fileBlocks);

		byte[] blockBuff=new byte[blockSize*K];		
		Element [] pdata=new Element[fileBlocks];			 
		FSDataInputStream in=hdfs.open(file);		
		int c;
		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）
		//StdOut.println("blockData->Zp：");
		for(int i=0;i<fileBlocks-1;i++){//处理前fileBlocks-1块			
			in.read(blockBuff);			
			pdata[i]=r.newElementFromHash(blockBuff,0,blockBuff.length);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
			//pdata[i]=r.newElementFromBytes(blockBuff);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
		//	System.out.print((i+1)+"block ");
		}
		c=in.read(blockBuff);
		in.close();
		if(c==blockSize*K){
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);
			//pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);
			System.out.print((fileBlocks)+"block ");
		}else{//最后一块可能不够，需特殊处理,采用0填充
			for(int k=c;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);			
			//pdata[fileBlocks-1]=r.newElementFromBytes(blockBuff);
			System.out.print((fileBlocks)+"block ");
			System.out.print("最后块大小："+c);
		}
		StdOut.println();
		return pdata;
	}
	/**
	 * 对文件进行预处理——分块和分段
	 * @param fileName	文件名
	 * @param blockSize	块大小
	 * @param s			每块的段数
	 * @param sectorSize	段大小
	 * @param r			大素数阶
	 * @return			n个文件块的域元素
	 * @throws IOException
	 */
	public Element[] preProcessFile(String fileName,int blockSize,int s,int sectorSize,Field r) throws IOException{
		Configuration conf = new Configuration();
		//获得一个与HDFS接口的FileSystem对象
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		//FileStatus存储文件和目录元信息
		FileStatus fstatus=hdfs.getFileStatus(file);
		
		//获得文件块数	   
		long fileSize=fstatus.getLen();
		int fileBlocks=(int)fileSize/(blockSize*K);
		long remain=fileSize%(blockSize*K);		
		fileBlocks=remain>0?fileBlocks+1:fileBlocks;
		//StdOut.println("文件大小:"+fileSize+"B ，文件块数:"+fileBlocks+",文件块大小："+blockSize+"K"+",段数"+s+"，段大小："+sectorSize);
		//int fileBlocks=getBlocksOfFile(hdfs, file, blockSize);

		byte[] blockBuff=new byte[blockSize*K];		
		Element [] pdata=new Element[fileBlocks];	
		//sectors=new HashMap<Integer,Object>(fileBlocks);//存放所有块的分段信息。
		sectors=new Element[fileBlocks][s];
		FSDataInputStream in=hdfs.open(file);		

		//这里可以采取多线程并行处理，生成域元素。（mapreduce的思想）
	//	StdOut.println("blockData->Zp,Sector：");
		for(int i=0;i<fileBlocks-1;i++){//处理前fileBlocks-1块			
			in.read(blockBuff,0,blockSize*K);			
			pdata[i]=r.newElementFromHash(blockBuff,0,blockBuff.length);//对数据进行域运算.这里使用hash（速度稍慢），也可以用newElementFromBytes
			sectors[i]=preProcessBlock(s, blockBuff, sectorSize, r);//第i块的分段信息加到sectors中
		//	System.out.print((i+1)+"block ");
		}
		int c=in.read(blockBuff);
		in.close();
		if(c==blockSize*K){//最后一块特殊处理
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);
			sectors[fileBlocks-1]=preProcessBlock(s, blockBuff, sectorSize, r);
		//	StdOut.println((fileBlocks)+"block ");
		//	StdOut.println("最后块大小："+c);
		}else{//最后一块可能不够，需特殊处理,采用0填充
			for(int k=c;k<blockBuff.length;k++){
				blockBuff[k]=0;			
			}
			pdata[fileBlocks-1]=r.newElementFromHash(blockBuff,0,blockBuff.length);	
			sectors[fileBlocks-1]=preProcessBlock(s, blockBuff, sectorSize, r);
			//StdOut.println((fileBlocks)+"block ");
			//StdOut.println("最后块大小："+c);
		}
		//StdOut.println();
		return pdata;
	}
	/**
	 * 对块进行分段处理
	 * @param s 		段数
	 * @param blockData 块数据
	 * @param sectorSize 段大小
	 * @param r 		素数域
	 * @return 			s个域元素	
	 */
	public Element[] preProcessBlock(int s,byte[] blockData,int sectorSize,Field r){

		Element[] sectorNums=new Element[s];
		for(int i=0;i<s;i++){
			sectorNums[i]=r.newElementFromHash(blockData,i*sectorSize,sectorSize);
		}
		return sectorNums;
	}

	/**
	 * 获得文件的块数
	 * @param fileName 文件名
	 * @param blockSize 块大小
	 * @return 文件块数
	 * @throws IOException
	 */
	public int getBlocksOfFile(String fileName,int blockSize) throws IOException{
		Configuration conf = new Configuration();		
		FileSystem hdfs=FileSystem.get(URI.create(hdfsPath),conf);
		Path file=new Path(hdfsPath+fileName);

		//FileStatus存储文件和目录元信息
		FileStatus fstatus=hdfs.getFileStatus(file);	 		
		//获得文件块数
		long fileSize=fstatus.getLen();
		int fileBlocks=(int)fileSize/(blockSize*K);
		long remain=fileSize%(blockSize*K);		
		//System.out.println("文件大小"+fileSize+" ，文件块数"+fileBlocks);
		return remain>0?fileBlocks+1:fileBlocks;
	}



	
	

}