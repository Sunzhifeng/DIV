package AssignTasks;

import java.util.Random;

import tool.DataFilter;
import tool.EnergyCost;
import tool.StdOut;

/**
 * 多个校验者分配数据块
 * @author MichaelSun
 * @since 2015.9.5
 *
 */
public class AssignTask {	
	public int S=BaseParams.S;
	public int M=BaseParams.M;		//文件大小，G
	public int n=BaseParams.n;
	public double pr=BaseParams.pr; //探测率	
	public int bs =BaseParams.bs;//数据块大小
	public int T=10;		     //用户期望完成时间
	public VerificationRequest vRequest=new VerificationRequest(M,n,T,pr);
	public MobileVerifier [] verifiers=new MobileVerifier[S];
		
	//未完成代码
	public void init(){
		for(int i=0;i<S;i++){
			verifiers[i]=new MobileVerifier(BaseParams.PsCPUi[i],
											BaseParams.PdCPUi[i],
											BaseParams.PsRFi[i],
											BaseParams.PdRFi[i],										
											BaseParams.wi[i]);
		}
	}
	
	/**
	 * 随机比率分配算法
	 * @param F		校验者工作频率集合
	 * @param W		校验者的存活时间集合
	 * @param r1	频率权重
	 * @return		分配给校验者的的数据块集合
	 */
	public void RandomRatioAssign(MobileVerifier [] verifiers, VerificationRequest VR){
		double []ws=new double[S];
		double sumW=0.0;		
		for(int i=0;i<S;i++){
			if(verifiers[i].w>VR.T)verifiers[i].w=T;
			sumW+=verifiers[i].w;			
		}
		//ni=min[nwi'/sum(wi'),gi(wi')]
		for(int i=0;i<S;i++){			
			int assign1=verifiers[i].verBlocks(verifiers[i].w);
			int assign2=(int)(VR.n*verifiers[i].w/sumW);
			verifiers[i].c=(assign1>assign2?assign2:assign1);			
		}
	}
	
	/**
	 * 能量有效的任务分配
	 * @param verifiers  校验者	
	 * @param VR	 校验需求
	 */
	public void  EEAVT(MobileVerifier [] verifiers, VerificationRequest VR){
		int remain=n;
		for(int i=0;i<S;i++){
			double t=(verifiers[i].w<VR.T?verifiers[i].w:VR.T);
			int assigni=verifiers[i].verBlocks(t);
			if(remain<=0)break;			
			verifiers[i].c=(remain-assigni>0?assigni:remain);			
			remain-=assigni;
		}
	}
	
	/**
	 * 单校验者分配算法
	 * @param verifiers
	 * @param VR
	 */
	public void singleAsign(MobileVerifier [] verifiers, VerificationRequest VR){
		
	}

	//能耗
	//校验需求
	
	//查找double数组中的最大元素
	public static double findmax(double[]a){
		double max=a[0];
		for(int i=1;i<a.length;i++){
			if(max<a[i])max=a[i];
		}
		return max;
	}

	public static void main(String []args){			
		
		/*//基本校验时间、完成时间范围
		double baseVerTimen=baseVerTime(n);
		double max=verTime(n, F[0]);
		double min=verTime(n/S,F[S-1]);
		
		//基本频率下的能耗
		double baseEnergyCost=EnergyCost.energyCost(baseVerTimen, f0);
		StdOut.println(baseVerTimen+"\t"+DataFilter.roundDouble(baseEnergyCost,3));

		//低频率，长时间获得最低能耗
		double minEnergy=EnergyCost.energyCost(max, F[0]);
		StdOut.println(max+"\t"+DataFilter.roundDouble(minEnergy,3));

		//高频率，短时间获得高能耗
		double maxEnergy=EnergyCost.energyCost(max, F[S-1])*S;
		StdOut.println(min+"\t"+DataFilter.roundDouble(maxEnergy,3));

		for(int k=0;k<1;k++){
			double r1=0.1+0.4*(k+1);//可变频率权重值			
			int [] ns=assignBlocks(F, W,1.5);//为每个校验者分配合适的数据块
			int sum=0;
		
			double energyCost=0.0;
			for(int j=0;j<S;j++){				
				energyCost+=EnergyCost.energyCost(fTime[j], F[j]);
			}			
		}*/
	}
}
