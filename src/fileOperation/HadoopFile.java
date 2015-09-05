/******************************************************
 ************** 客户端用户操作HDFS中的文件****************
 ******************************************************
 */

package fileOperation;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.io.IOUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;
public class HadoopFile {
	//public static String hdfsPath="hdfs://master:9000/user/sunzhifeng/input";

	/**
	 * 将单个本地文件上传到hadoop中
	 * @param localfile 本地文件路径
	 * @param hdfsDirectory hdfs文件目录
	 * @throws Exception
	 */
	public static void upload(String localfile,String hdfsDirectory) throws Exception {
		Configuration conf = new Configuration();		
		FileSystem hdfs = FileSystem.get(URI.create(hdfsDirectory),conf);
		Path src = new Path(localfile);
		Path dst = new Path(hdfsDirectory);

		//执行上传操作，并打印提示信息
		hdfs.copyFromLocalFile(src, dst);
		System.out.println("Upload to " +hdfsDirectory);

		listFiles(hdfs,dst);

	}
	/**
	 * 将HDFS中的某个文件下载到本地
	 * @param hdfsFile		要下载的文件
	 * @param localPath		本地路径	
	 * @throws Exception
	 */
	public static void download(String hdfsFile,String localPath)throws Exception{
		Configuration conf = new Configuration();			
		FileSystem hadoopFS=FileSystem.get(URI.create(hdfsFile),conf);
		Path hdfsPath=new Path(hdfsFile);
		FSDataInputStream fsIn=hadoopFS.open(hdfsPath);
		OutputStream fsout = new FileOutputStream(localPath+"/"+hdfsPath.getName());  
		IOUtils.copyBytes(fsIn, fsout, 4096,true);
		System.out.println("Download to " +localPath);

	}


	/**
	 * 删除HDFS中的某个文件 	
	 * @param hdfsfile	要删除的文件名——绝对路径
	 * @throws Exception
	 */
	public static void delete(String hdfsfile) throws Exception {
		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsfile),conf);		
		Path hdfsPath = new Path(hdfsfile);
		boolean exit=hdfs.exists(hdfsPath);
		if(!exit){
			System.err.println(hdfsPath.getName()+"is not exist!can't delete！");
			return;
		}
		Path p= hdfsPath.getParent();//获得删除文件或目录的父目录
		boolean ok = hdfs.delete(hdfsPath, true);//删除目录设置true
		System.out.println(ok ? "delete successfully!" : "delete unsuccessfully! ");

		//当前目录下的文件
		listFiles(hdfs,p);

	}

	/**
	 * 读取HDFS文件内容
	 * @param hdfsfile 	hadoop中的文件
	 * @throws Exception
	 */
	public void testRead(String hdfsfile) throws Exception {
		Configuration conf = new Configuration();
		//获得一个与HDFS接口的FileSystem对象
		FileSystem hdfs=FileSystem.get(URI.create(hdfsfile),conf);
		InputStream in=null;
		in=hdfs.open(new Path(hdfsfile));
		IOUtils.copyBytes(in, System.out, 4096,false);

	}



	/**
	 * 重命名HDFS上的用户文件
	 * @param hdfsPath    文件所在目录
	 * @param oldFilename 旧文件名
	 * @param newFilename 新文件名
	 * @throws Exception
	 */
	public static void rename(String hdfsPath,String oldFilename,String newFilename) throws Exception {

		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsPath),conf);
		Path frpath = new Path(hdfsPath +"/"+ oldFilename);
		Path topath = new Path(hdfsPath +"/"+ newFilename);			
		hdfs.rename(frpath, topath);//改名			
		listFiles(hdfs, new Path(hdfsPath));//查看文件列表
	}


	// 查看HDFS文件的最后修改时间
	public static void getModifyTime(String hdfsPath) throws Exception {		
		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsPath),conf);
		Path dst = new Path(hdfsPath);
		FileStatus files[] = hdfs.listStatus(dst);
		for (FileStatus file : files) {		
			System.out.println(file.getPath() + "\t"
					+ new Date(file.getModificationTime()));

		}
	}

	// 查看HDFS文件是否存在
	public static void Exists(String hdfsFile) throws Exception {

		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsFile),conf);
		Path hdfsPath = new Path(hdfsFile);
		boolean ok = hdfs.exists(hdfsPath);
		System.out.println(ok ? "文件存在" : "文件不存在");
	}

	// 查看某个文件在HDFS集群的位置
	public static void fileBlockLocation(String hdfsFile) throws Exception {

		Configuration conf = new Configuration();
		FileSystem hdfs = FileSystem.get(URI.create(hdfsFile),conf);
		Path dst = new Path(hdfsFile);
		FileStatus fileStatus = hdfs.getFileStatus(dst);
		BlockLocation[] blockLocations = hdfs.getFileBlockLocations(fileStatus,
				0, fileStatus.getLen());
		for (BlockLocation block : blockLocations) {
			System.out.println(Arrays.toString(block.getHosts()) + "\t"
					+ Arrays.toString(block.getNames()));
		}
	}

	// 获取HDFS集群上所有节点名称
	public static void getHostName() throws Exception {

		Configuration conf = new Configuration();
		DistributedFileSystem hdfs = (DistributedFileSystem) FileSystem
				.get(URI.create("hdfs://master:9000/"),conf);
		DatanodeInfo[] dataNodeStats = hdfs.getDataNodeStats();

		for (DatanodeInfo dataNode : dataNodeStats) {
			System.out.println(dataNode.getHostName() + "\t"
					+ dataNode.getName());
		}
	}

	/**
	 * 查看HDFS中指定目录下的文件列表
	 * @param hdfs	 文件系统标识	
	 * @param dir	指定查看的目录
	 * @throws IOException
	 */
	public static  void listFiles(FileSystem hdfs,Path dir) throws IOException{

		FileStatus files[] = hdfs.listStatus(dir);
		System.out.println(dir+":");
		for (FileStatus file : files) {
			System.out.println(file.getPath().getName());
		}

	}
	/**
	 * 查看HDFS中指定目录下的文件列表	
	 * @param dir	指定查看的目录
	 * @throws IOException
	 */
	public static void listFiles(String dir) throws IOException{		
		Configuration conf = new Configuration();
		FileSystem hdfs=FileSystem.get(URI.create(dir),conf);
		FileStatus files[] = hdfs.listStatus(new Path(dir));
		System.out.println(dir);
		for (FileStatus file : files) {
			System.out.println(file.getPath().getName());
		}
	}

	public static void main(String[] args) throws Exception {
		String split="/";
		String localDirectory="D:/test";
		String localfile="test-2.txt";
		String hdfsDirectory="hdfs://master:9000/user/sunzhifeng/input/";

		//HadoopFile.listFiles(hdfsDirectory);
		HadoopFile.upload(localDirectory+split+localfile, hdfsDirectory);
		// HadoopFile.download(hdfsDirectory+split+"hello.txt", localDirectory);
		// HadoopFile.delete(hdfsDirectory+split+"test-2.txt");
		// HadoopFile.getModifyTime(hdfsDirectory);
		// HadoopFile.fileBlockLocation(hdfsDirectory+split+"hello.txt");
		// HadoopFile.getHostName();
		// HadoopFile.rename(hdfsDirectory+split, "hello.txt", "hello01.txt");

	}
}