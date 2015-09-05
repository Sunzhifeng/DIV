package MHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import tool.Sampling;
import tool.StdOut;
import tool.Stopwatch;
import MHT.MHTPADD_03.Chal;


/**
 * MHTPADD_03进行测试
 * @author MichaelSun
 * @version 3.0
 * @date 2014.12.16
 */
public class TestMHTPADD_03 {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";	
		int c=30;					//挑战的块数量
		int s;				//每块的段数
		int sectorSize=20;		//160bit	
		double p=0.999;			//探测率
		int e=10;				//损坏的块数（实际中是不可预知的）
		//int []sampleC={20,40,60,80,100,120,140,160};
		int [] sPerBlock={100,200,300,400,500,600,700,800,900,1000};		
		for(int count=0;count<sPerBlock.length;count++){
			//StdOut.println("count:"+(count+1));
			s=sPerBlock[count];
			//c=sampleC[count];			
			StdOut.print(s+"\t");
			int blockSize=s*sectorSize/1000;//以k为单位
			//Stopwatch start=new  Stopwatch();	//计时器
			HDFSFileOperation fileOper=new HDFSFileOperation();		
			MHTPADD_03 mhtPDP=new MHTPADD_03(false,"pairing/d/d_159.properties");	

			//StdOut.println("\n==============DataOwner==============\n");

			//初始设置
			//StdOut.println("-------------初始化参数设置------------");
			mhtPDP.setup();


			//对文件进行预处理
			//StdOut.println("\n-------------对文件预处理------------");
			Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, mhtPDP.getPairing().getZr());
			Element[][] sectors=HDFSFileOperation.sectors;
			Element[] gdata=mhtPDP.allGElement(pdata);
			int fileBlocks=fileOper.getBlocksOfFile(fileName, blockSize);
			//c=Sampling.getSampleBlocks(fileBlocks,e,p);
		//	StdOut.print(fileBlocks+"\t");	
			//	StdOut.println("采样块数："+c);
			//StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");

			//密钥生成
		//	StdOut.println("\n-------------生成密钥------------");
			Map<String,Element> keyMap=mhtPDP.keyGen();    

			//生成随机数
			Element[]ps=mhtPDP.psGen(s);
			Element[] us=mhtPDP.usGen(ps);	

			//元数据生成		
		//	StdOut.println("\n-------------计算每块的标签------------");
			Stopwatch DOTime=new  Stopwatch();	//计时器
			Stopwatch taggenTime=new  Stopwatch();	//计时器
			Element[] blockTags=new Element[fileBlocks];	
			for(int i=0;i<fileBlocks;i++){				
				blockTags[i]=mhtPDP.metaGen(i,gdata[i],keyMap.get(MHTPADD_03.SECRETKEY),sectors[i],ps);
			}		
			StdOut.print(taggenTime.elapsedTime()/1000+"\t");
			//构建MHT树并对Root进行签名,签名长度512*4=2048bit
			//StdOut.println("\n-------------构建哈希树并对树根进行签名------------");
			//Stopwatch mhtTime=new  Stopwatch();	//计时器
			MerkleHashTree mht=new MerkleHashTree(gdata);
			byte[] Root=mht.createMHT();				
			Element sigHashRoot=mhtPDP.sigRoot(Root, keyMap.get(MHTPADD_03.SECRETKEY));
			//StdOut.println("耗时："+mhtTime.elapsedTime());
			double temp1=DOTime.elapsedTime()/1000;
			StdOut.print(temp1+"\t");

		//	StdOut.println("\n==============verifier==============\n");

			//发起挑战
			//StdOut.println("\n-------------产生挑战信息------------");
			Chal [] challenge=mhtPDP.challengeGen(c,fileBlocks);
			//StdOut.println("\n-------------发出挑战------------");

			//StdOut.println("\n==============Cloud Service Provider==============\n");
			//服务器根据挑战信息，获得证据的元数据
			int [] blockNumChall=new int[c];//块号
			Element [] vi=new Element[c];//随机数
			Element [][] mij=new Element[c][s];//存放挑战块的段信息
			Element [] ti=new Element[c];//块标签	
			Element [] Hmi =new Element[c];
			Stopwatch genProofTime=new  Stopwatch();	//计时器
			for(int i=0;i<c;i++){
				blockNumChall[i]=challenge[i].num;
				vi[i]=challenge[i].random;
				ti[i]=blockTags[challenge[i].num-1];
				for(int j=0;j<s;j++)
					mij[i][j]=sectors[challenge[i].num-1][j];	//实现生成了pdata，服务器保存		
				Hmi[i]=gdata[challenge[i].num-1];			
			}
			//StdOut.println("-------------获得校验请求信息------------");

			//服务器生成证据	
			//StdOut.println("-------------生成证据------------");
			
			Map<String,Object>aai=mht.genChalAAI(blockNumChall);//计算辅助索引空间 


			Map<String,Object>proof=mhtPDP.genProof(vi, mij, ti,s);		
			proof.put("AAI",aai);
			proof.put("Hmi",Hmi);//Hmi中的值顺序对应与挑战编号的顺序
			proof.put("sigHashRoot",sigHashRoot);	
			//StdOut.println(proof);
			double temp2=genProofTime.elapsedTime()/1000;
			StdOut.print(temp2+"\t");


		//	StdOut.println("\n==============verifier==============\n");

			Stopwatch verProofTime=new  Stopwatch();	//计时器
			//校验者根据块信息计算Root
		//	StdOut.println("-------------计算并验证Root------------");
			byte[] newRoot=mht.getRootByAuxiliaryIndex(aai,blockNumChall);

			//StdOut.println("\n-------------验证数据块------------");
			boolean rTrue=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_03.PUBLICKEY),us,challenge, proof);
		//	boolean rFalse2=mhtPDP.proofVerify(Root, keyMap.get(MHTPADD_03.PUBLICKEY).twice(), us,challenge,proof);
			//proof.put("sigHashRoot", sigHashRoot.twice());
			//boolean rFalse1=mhtPDP.proofVerify(newRoot, keyMap.get(MHTPADD_03.PUBLICKEY), us,challenge,proof);
			double temp3=verProofTime.elapsedTime()/1000;
			StdOut.print(temp3+"\t");
			StdOut.println((temp1+temp2+temp3)+"\t");

			//验证结果
			assertTrue(rTrue);
			//assertFalse(rFalse1);
			//assertFalse(rFalse2);
			//StdOut.println("\n-------------证据有效，数据完整------------");

			//StdOut.println("总耗时："+start.elapsedTime()+"ms");
		}
	

	}
}
