package LyaOptimal;

public class Task{
	public static final int COMPLETED=1;
	public static final int WAITING=0;
	public static final int RUNNING=2;
	int id;		//任务编号
	double c;		//任务量
	double t; 		//任务完成时间限制
	int state;  //任务的状态：0等待；1完成；2正在执行
	public Task(int id,double c,double t){
		this.id=id;
		this.c=c;
		this.t=t;
	}
}