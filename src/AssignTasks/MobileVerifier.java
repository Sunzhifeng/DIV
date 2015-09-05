package AssignTasks;

import tool.DataFilter;

//移动校验者
public class MobileVerifier {	
	public double PsCPU;//静态计算功率
	public double PdCPU;//动态增加的计算功率
	public double PsRF;//静态传输功率
	public double PdRF;//动态增加传输功率
	public int w;	   //存活时间
	public double st; //校验者提供的校验服务时间
	public int c;	//分给校验者的校验任务（块数）
	//public VerificationTask verTask;//分给校验者的校验任务
	
	//min constructor
	public MobileVerifier(){}
	
	//max constructor
	public MobileVerifier(double PsCPU, double PdCPU, double PsRF,double PdRF,int w){
		this.PsCPU=PsCPU;
		this.PdCPU=PdCPU;
		this.PsRF=PsRF;
		this.PdRF=PdRF;
		this.w=w;		
	}
		
	/**
	 * 证据检查计算时间
	 * @param x		检查块数	 
	 * @return  	检查时间
	 */
	public double verTime(int x){
		return DataFilter.roundDouble((BaseParams.Ps0CPU+BaseParams.Pd0CPU)*BaseParams.baseVerTime(x)/(PsCPU+PdCPU),3);
	}	
	
	/**
	 * 给定时间内可校验的
	 * @param time
	 * @return
	 */
	public int verBlocks(double t){
		return 0;
	}
	
	/**
	 * 根据时间消耗计算校验者的能量消耗(计算消耗和传输消耗）
	 * @param TsCPU		静态CPU运行时间
	 * @param TdCPU		动态CPU运行时间
	 * @param TsRF		静态RF传输时间
	 * @param TdRF		动态RF传输时间
	 * @return			消耗的总能量
	 */
	public  double verEnergy(double TsCPU,double TdCPU,double TsRF,double TdRF){
		return verComputeEnergy(TsCPU,TdCPU)+verTransEnergy(TsRF,TdRF);
	}
	
	//计算能耗
	private  double verComputeEnergy(double t1,double t2){
		return PsCPU*t1+PdCPU*t2;
	}

	//传输能耗
	private  double verTransEnergy(double t1,double t2){
		return PsRF*t1+PdRF*t2;
	}

	
/*	public VerificationTask getVerTask() {
		return verTask;
	}

	public void setVerTask(VerificationTask verTask) {
		this.verTask = verTask;
	}
*/
}
