package AssignTasks;

import tool.DataFilter;

//云服务器
public class CloudServer {
	public double f; //云服务器的工作频率
	public static final int k=1;	//能耗系数
	public static final int a=3;
	public CloudServer(double f){
		this.f=f;		
	}
	
	/**
	 * 服务器计算证据时间
	 * @param x 校验的块数
	 * @return  计算证据时间
	 */
	public  double proofTime(int x){
		return DataFilter.roundDouble(BaseParams.f0*BaseParams.baseCSTime(x)/f,3);
	}
	
	/**
	 * 给定时间内可校验最大块数
	 * @param time	 
	 * @return
	 */
	public int verBlocks(double time)
	{
		return BaseParams.verBlocks(time,f);	
	}
	
	/**
	 * 计算服务器的能量消耗——t*k*(f^a)
	 * @param Tcsp
	 * @return
	 */
	public double CSPEnergy(double Tcsp){
		return Tcsp*k*Math.pow(f, a);
	}

	public double energyCost(double t,double f){
		return t*k*Math.pow(f, a);
	}

}
