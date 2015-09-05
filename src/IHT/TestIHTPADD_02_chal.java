package IHT;

import static org.junit.Assert.assertTrue;
import fileOperation.FileOperation;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import tool.DataFilter;
import tool.EnergyCost;
import tool.PropertiesUtil;
import tool.StdOut;
import tool.Stopwatch;
import FEPAD.TransferCost;
import IHT.IndexHashTable.Item;

/**
 * 固定块数分多次挑战进行校验的时间消耗
 * @author MichaelSun
 * @version 1.0
 * @date 2014.1.05
 */
public class TestIHTPADD_02_chal {		

	public static void main (String [] args) throws Exception{
		PropertiesUtil p=new PropertiesUtil();
		String fileName="d:/test/test-2.txt";	
		int  q=30;		//CSP的处理速度是校验者的q倍
		int  w=50;		//单位KB/s		
		int []challCounts={1,2,3,5,6,10,15,30};
		int c=30;					//挑战的块数量
		int s=400;					//每块的段数
		int sectorSize=20;		//160bit			
		int [] samplec={47,135,130,172,4,79,247,6,199,204,238,181,65,246,158,
				67,22,114,136,85,170,145,11,94,200,14,229,106,102,179};

		//int [] eBlocks=GenerateRandom.random(1, samplec.length, 3); 
		int [] eBlocks={14,22,27};	
		
		for(int count=0;count<1;count++){						
			StdOut.println("s="+s+",\t"+"c="+c+",\tq="+q+",\tw="+w+"KB/s");
			int blockSize=s*sectorSize/1000;//以k为单位			
			IHTPADD_02 ihtPADP=new IHTPADD_02(false,"pairing/d/d_159.properties");

			//初始设置
			ihtPADP.setup();

			//对文件进行预处理
			Map<String,Object> preData=FileOperation.preProcessFile(fileName, blockSize,s,sectorSize, ihtPADP.getPairing().getZr());
			Element[] pdata=(Element[])preData.get("pdata");
			List<Element[]> nSectors=(List<Element[]>)preData.get("nSectors");	
			int fileBlocks=FileOperation.blockNumbersOfFile(fileName, blockSize);

			//生成随机数
			Element[] ps = ihtPADP.psGen(s);
			Element[] us = ihtPADP.usGen(ps);

			//密钥生成
			Map<String,Element> keyMap=ihtPADP.keyGen();    

			//构建索引哈希表IHT
			double DoTime=0.00;
			Stopwatch IHTTime=new  Stopwatch();	//计时器	
			IndexHashTable ihtable=new IndexHashTable(fileName,fileBlocks);			
			Item [] item=ihtable.createIHT2(ihtPADP.getPairing().getZr(),keyMap.get(ihtPADP.SECRETKEY) , ihtPADP.getPairing().getG1(),pdata);		
			Element[] Hid=ihtable.getHids();			
			DoTime+=IHTTime.elapsedTime();

			//元数据生成
			Element[] blockTags=new Element[fileBlocks];		
			Stopwatch genTagTime=new  Stopwatch();	//计时器
			for(int i=0;i<fileBlocks;i++){				
				blockTags[i]=ihtPADP.metaGen(i,Hid[i+1],keyMap.get(IHTPADD_02.SECRETKEY),nSectors.get(i),ps);
			}	
			DoTime+=genTagTime.elapsedTime();	
			DoTime=DataFilter.roundDouble(DoTime/1000, 3);
			StdOut.println("dataOwner Time Cost(s): "+DoTime);
			double CSPTime=0.00;
			double VerTime=0.00;
			double transTime=0.00;
			double transCost=0.00;//kb
			//测试多次挑战
			int challCount=3;
			for(int n=0;n<challCounts.length;n++){
				challCount=challCounts[n];
				for(int m=0;m<challCount;m++){
					int cChal=c/challCount;//每次挑战的块数
					int startNum=1+m*cChal;//第一块
					int endNum=startNum+cChal-1;
					//产生挑战的随机标识r
					Element r=ihtPADP.rGen();
					Map<String,Object> challengeKR=ihtPADP.challengeGen3(samplec,startNum,endNum,keyMap.get(IHTPADD_02.PUBLICKEY),r,fileName);

					//服务器根据挑战信息，获得证据的元数据					
					int [] blockNumChall=(int[])challengeKR.get("blocknum");	//块号
					Element R=(Element)challengeKR.get("R");	//本次挑战的随机标志		
					BigInteger k1=(BigInteger)challengeKR.get("k1");//生成随机数的hash密钥键				
					Element [][] mij=new Element[cChal][s]; //存放挑战块的段信息
					Element [] ti=new Element[cChal];		//块标签	
					Item [] id =new Item[cChal]; 			//挑战块的IHT中的表项
					Stopwatch genProofTime=new  Stopwatch();	//计时器	
					Element [] vi=ihtPADP.randomVi(cChal, blockNumChall, k1, ihtPADP.getPairing().getZr());		//随机数
					for(int i=0;i<cChal;i++){				
						ti[i]=blockTags[blockNumChall[i]-1];
						for(int j=0;j<s;j++)
							mij[i][j]=nSectors.get(blockNumChall[i]-1)[j];	//实现生成了pdata，服务器保存		
						id[i]=item[blockNumChall[i]];			
					}

					//服务器生成证据		
					Map<String,Object>proof=ihtPADP.genProof4(vi, mij, ti,R,us);
					proof.put("id",id);		//返回挑战块的ID
					CSPTime+=genProofTime.elapsedTime();				

					//检查证据
					Stopwatch verproofTime=new  Stopwatch();	//计时器
					boolean rTrue=ihtPADP.proofVerify2( keyMap.get(IHTPADD_02.PUBLICKEY),r,challengeKR,proof,fileName);
					assertTrue(rTrue);	
					VerTime+=verproofTime.elapsedTime();
					transCost+=TransferCost.IHTPADDTransCost(cChal, 256, 20);
				}	

				CSPTime=DataFilter.roundDouble(CSPTime/(q*1000),3);				
				VerTime=DataFilter.roundDouble(VerTime/1000, 3);
				transCost=DataFilter.roundDouble(transCost, 3);
				transTime=DataFilter.roundDouble(transCost/w, 3);
				double total=DataFilter.roundDouble(CSPTime+VerTime+transTime,3);
				StdOut.println(challCount+"\t"+CSPTime+"\t"+VerTime+"\t"+transTime+"\t"+total);
				//StdOut.println(transCost+"KB");
			}

		}
	}
}
