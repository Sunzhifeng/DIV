package LyaOptimal;

import java.util.ArrayList;
import java.util.List;

public class Server{  
	public static final int IDLE=0; //服务器空闲
	public static final int COMPUTING=1;//服务器计算
	public static final int TASKBUFF=1;
	public static final double Q0=0.0;  //初始任务时间队列长度为0.0
	public  int task=0;
	int id; 	//服务器编号
	double s;		//服务器的计算速度	
	double queueTime;	//服务器的队列长度，表现在还需要计算的时间
	List<Integer>  tasksBuff;
	int state;		//服务器的状态：0.空闲等待；1.工作状态
	public Server(){

	}
	public Server(int id ,double s,double queueTime,int taskBuff,int state ){
		this.id=id;
		this.s=s;	
		this.queueTime=queueTime;
		this.tasksBuff=new ArrayList<Integer>(taskBuff);
		this.state=state;
	}
}
