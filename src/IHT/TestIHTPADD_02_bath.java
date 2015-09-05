package IHT;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import fileOperation.HDFSFileOperation;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

import IHT.IHTPADD_02.Chal;
import IHT.IndexHashTable.Item;
import tool.StdOut;
import tool.Stopwatch;

/**
 * 测试MHTPADD_02的功能批量校验功能
 * @author MichaelSun
 *
 */
public class TestIHTPADD_02_bath {

	public static void main (String [] args) throws Exception{
		String fileName="test-2.txt";
		int s=200;				//每块的段数
		int sectorSize=20;		//160bit
		int blockSize=s*sectorSize/1000;//以k为单位				
		int K=2;		//一次对两个用户的文件进行校验
		int [] kc={23,23};//每个挑战都为6块
		//计时器
		Stopwatch start=new  Stopwatch();
		HDFSFileOperation fileOper=new HDFSFileOperation();		
		IHTPADD_02 ihtPADD=new IHTPADD_02(false,"pairing/d/d_159.properties");	

		StdOut.println("\n==============DataOwner==============\n");

		//初始设置
		StdOut.println("-------------初始化参数设置------------");
		ihtPADD.setup();

		//生成密钥和随机值
		Map<Integer,Map<String,Element>> userKeys=new HashMap<Integer,Map<String,Element>>(K);
		List<Element []>kus=new ArrayList<Element[]>(K);
		List<Element []>kps=new ArrayList<Element[]>(K);
		for(int k=0;k<K;k++){
			userKeys.put(k, ihtPADD.keyGen());//密钥生成			
			kps.add(ihtPADD.psGen(s));
			kus.add(ihtPADD.usGen(kps.get(k)));//用户秘密值			
		}
		List<Element> hashKeys=new ArrayList<Element>(K);
		for(int j=0;j<K;j++){
			hashKeys.add(ihtPADD.hashKeyGen(kps.get(j),userKeys.get(j).get(ihtPADD.SECRETKEY)));
		}

		//对文件进行预处理
		StdOut.println("\n-------------对文件预处理------------");
		Element[] pdata=fileOper.preProcessFile(fileName, blockSize,s,sectorSize, ihtPADD.getPairing().getZr());
		Element[][] sectors=HDFSFileOperation.sectors;
		//Element[] gdata=ihtPADD.allGElement(pdata);		
		int fileBlocks=pdata.length;		
		StdOut.println("文件预处理耗时："+start.elapsedTime()+"ms");

		StdOut.println("\n-------------构建索引哈希表------------");
		IndexHashTable[] ihtables=new IndexHashTable[K];
		List<Item[]> kItems=new ArrayList<Item[]>(K);
		for(int k=0;k<K;k++){		
			
			//构建索引哈希表IHT
			ihtables[k]=new IndexHashTable(fileName,fileBlocks);			
			kItems.add(ihtables[k].createIHT2(ihtPADD.getPairing().getZr(),hashKeys.get(k) , ihtPADD.getPairing().getG1(),pdata));		
			
		}
		StdOut.println("\n-------------"+K+"个用户生成元信息------------");
		Stopwatch dataOwnerTime=new Stopwatch();
		Element[][]kblockTags=new Element[K][fileBlocks];		
		for(int k=0;k<K;k++){			
			Element[] Hid=ihtables[k].getHids();//Hid的0位置存放的是ZeroElement
			//元数据生成				
			for(int i=0;i<fileBlocks;i++){		
				kblockTags[k][i]=ihtPADD.metaGen(i,Hid[i+1],userKeys.get(k).get(ihtPADD.SECRETKEY),sectors[i],kps.get(k));
			}

		}
		StdOut.println("DO耗时："+dataOwnerTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		StdOut.println("\n-------------产生挑战信息------------");
		List<Map<String,Object>> kchallengeRs=new ArrayList<Map<String,Object>>(K);		
		Element r=ihtPADD.rGen();//一次校验对应一个r
		for(int k=0;k<K;k++){		
			kchallengeRs.add(ihtPADD.challengeGen(kc[k],fileBlocks,userKeys.get(k).get(ihtPADD.PUBLICKEY),r,fileName));
		}
		StdOut.println("\n-------------发出挑战------------");



		StdOut.println("\n==============Cloud Service Provider==============\n");

		Stopwatch cspTime=new Stopwatch();
		StdOut.println("-------------生成证据------------");	
		List<Element[][]> kmij=new ArrayList<Element[][]>(K);		
		List<Element[]> kti=new ArrayList<Element[]>(K);
		List<Item[]> kid=new ArrayList<Item[]>(K);
		//服务器对挑战的元信息进行处理
		for(int k=0;k<K;k++){
			Chal[] chal=(Chal[])kchallengeRs.get(k).get("challenge");
			int CBCounts=chal.length;//挑战的块的数量
			Item [] item=kItems.get(k);
			Element[][] mij=new Element[CBCounts][s];
			Element[] ti=new Element[CBCounts];	
			Item[] id=new Item[CBCounts];
			for(int i=0;i<CBCounts;i++){					
				ti[i]=kblockTags[k][chal[i].num-1];
				id[i]=item[chal[i].num];
				for(int j=0;j<s;j++){
					mij[i][j]=sectors[chal[i].num-1][j];//读取数据
				}
				
			}
			kmij.add(mij);			
			kti.add(ti);
			kid.add(id);
		}

		//数据累加和标签累乘
		Map<String,Object>proof=ihtPADD.genBathProof(kchallengeRs, kmij, kti,kus,s);	
		proof.put("kid", kid);
		StdOut.println(proof);
		StdOut.println("csp耗时："+cspTime.elapsedTime()+"ms");


		StdOut.println("\n==============verifier==============\n");
		Stopwatch verTime=new  Stopwatch();	
		StdOut.println("\n-------------验证证据------------");
		//检查证据
		Element[] kPublicKeys=new Element[K];
		for(int k=0;k<K;k++){
			kPublicKeys[k]=userKeys.get(k).get(IHTPADD_02.PUBLICKEY);
		}
		boolean rTrue=ihtPADD.proofBathVerify(kPublicKeys,r,kchallengeRs,proof,fileName);
		boolean rFalse1=ihtPADD.proofBathVerify(kPublicKeys,r.duplicate().twice(),kchallengeRs,proof,fileName);//MHT的root错误
		Element D=(Element)proof.get("kaggreDMul");
		proof.put("kaggreDMul", D.twice());
		boolean rFalse2=ihtPADD.proofBathVerify(kPublicKeys,r,kchallengeRs,proof,fileName);

		StdOut.println("耗时："+verTime.elapsedTime()+" ms.");		
		//验证结果
		assertTrue(rTrue);
		assertFalse(rFalse1);
		assertFalse(rFalse2);
		StdOut.println("\n-------------证据有效，数据完整------------");
		StdOut.println("总耗时："+start.elapsedTime()+" ms.");
	}

}
