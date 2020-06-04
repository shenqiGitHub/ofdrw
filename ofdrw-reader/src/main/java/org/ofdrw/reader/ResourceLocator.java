package org.ofdrw.reader;

import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.Node;
import org.ofdrw.core.basicType.ST_Loc;
import org.ofdrw.pkg.container.*;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * 资源定位器
 * <p>
 * 通过给与的资源地址获取对应的资源文件或对象
 *
 * @author 权观宇
 * @since 2020-04-08 20:05:14
 */
public class ResourceLocator {

    /**
     * 路径匹配正则列表
     */
    public static Pattern PtDoc = Pattern.compile("/(Doc_\\d+)");
    public static Pattern PtSigns = Pattern.compile("/(Doc_\\d+)/Signs");
    public static Pattern PtSign = Pattern.compile("/(Doc_\\d+)/Signs/(Sign_\\d+)");
    public static Pattern PtPages = Pattern.compile("/(Doc_\\d+)/Pages");
    public static Pattern PtPage = Pattern.compile("/(Doc_\\d+)/Pages/(Page_\\d+)");
    public static Pattern PtPageRes = Pattern.compile("/(Doc_\\d+)/Pages/(Page_\\d+)/Res");
    public static Pattern PtDocRes = Pattern.compile("/(Doc_\\d+)/Res");

    /**
     * 当前目录
     */
    private LinkedList<String> workDir;
    /**
     * 资源容器
     * <p>
     * 该容器带有缓存功能
     */
    private OFDDir ofdDir;

    /**
     * 保存的路径栈
     * <p>
     * 每次调用Save都会入栈
     */
    private LinkedList<LinkedList<String>> savedStack;

    private ResourceLocator() {

    }

    public ResourceLocator(OFDDir ofdDir) {
        this.ofdDir = ofdDir;
        // 默认工作目录为OFD容器的根目录
        this.workDir = new LinkedList<>();
        this.savedStack = new LinkedList<>();
        this.workDir.add("/");
    }

    /**
     * 保存当前工作路径
     *
     * @return this
     */
    public ResourceLocator save() {
        LinkedList<String> toBeSaveWd = new LinkedList<>(workDir);
        // 入栈
        savedStack.addFirst(toBeSaveWd);
        return this;
    }

    /**
     * 还原原有工作区
     * <p>
     * 如果没有保存过工作区，那么不会造成任何影响
     *
     * @return this
     */
    public ResourceLocator restore() {
        if (!savedStack.isEmpty()) {
            workDir.clear();
            // 出栈
            LinkedList<String> lastSaved = savedStack.removeFirst();
            workDir.addAll(lastSaved);
        }
        return this;
    }

    /**
     * 转换路径对象为绝对路径字符串
     *
     * @param path 路径对象
     * @return 绝对路径字符串
     */
    public String toAbsolutePath(ST_Loc path) {
        if (path == null) {
            return pwd();
        }
        return toAbsolutePath(path.getLoc());
    }

    /**
     * 路径转换为绝对路径
     *
     * @param path 容器路径
     * @return 绝对路径字符串
     */
    public String toAbsolutePath(String path) {
        if (path == null || path.trim().isEmpty()) {
            return pwd();
        }
        LinkedList<String> workDirCopy = new LinkedList<>(workDir);
        if (path.startsWith("/")) {
            workDirCopy.clear();
            workDirCopy.add("/");
        }
        for (String item : path.split("/")) {
            item = item.trim();
            if (item.equals(".") || item.isEmpty()) {
                // 表示但前目录不做任何操作
                continue;
            } else if (item.equals("..")) {
                workDirCopy.removeLast();
                if (workDirCopy.isEmpty()) {
                    workDirCopy.add("/");
                }
            } else {
                workDirCopy.add(item);
            }
        }
        return pwd(workDirCopy);
    }


    /**
     * 重置工作路径
     * <p>
     * 重置后将回到根路径
     *
     * @return this
     */
    public ResourceLocator restWd() {
        return cd("/");
    }


    /**
     * 切换到制定的虚拟容器目录下
     *
     * @param vc 虚拟容器
     * @return this
     */
    public ResourceLocator cd(VirtualContainer vc) {
        if (vc == null) {
            throw new IllegalArgumentException("改变目录的容器对象（vc）为空");
        }
        return cd(vc.getAbsLoc().getLoc());
    }

    /**
     * 改变目录  Change Directory
     *
     * @param path 路径位置
     * @return this
     * @throws ErrorPathException 路径不存在
     */
    public ResourceLocator cd(String path) {
        return cd(workDir, path);
    }

    /**
     * 改变目录  Change Directory
     * <p>
     * 路径最后如果是目录也不加 "/"
     *
     * @param path    路径位置
     * @param workDir 已有工作目录
     * @return this
     * @throws ErrorPathException 路径不存在
     */
    public ResourceLocator cd(LinkedList<String> workDir, String path) {
        if (path == null || path.equals("")) {
            return this;
        }
        path = path.trim();
        if (path.equals("/")) {
            workDir.clear();
            workDir.add("/");
            return this;
        }
        // 转换路径为绝对路径
        String absPath = toAbsolutePath(path);
        String ofwTmp = ofdDir.getSysAbsPath();
        Path sysPath = Paths.get(ofwTmp + absPath);
        if (Files.exists(sysPath) && Files.isDirectory(sysPath)) {
            // 刷新工作区到指定区域
            workDir.clear();
            workDir.add("/");
            for (String item : absPath.split("/")) {
                item = item.trim();
                if (item.isEmpty()) {
                    continue;
                }
                workDir.add(item);
            }
        } else {
            // 如果路径不存在，那么报错
            throw new ErrorPathException("无法切换路径到" + path + "，目录不存在。");
        }
        return this;
    }

    /**
     * 判断路径是否存在
     *
     * @param workDir 路径集合
     * @return true -存在，false - 不存在
     */
    public boolean exist(LinkedList<String> workDir) {
        String pwd = pwd(workDir);
        String ofwTmp = ofdDir.getSysAbsPath();
        Path path = Paths.get(ofwTmp + pwd);
        return Files.exists(path);
    }


    /**
     * 判断路径是否存在
     *
     * @param workDir 工作路径
     * @return true -存在，false - 不存在
     */
    public boolean dirExit(LinkedList<String> workDir) {
        String pwd = pwd(workDir);
        String ofwTmp = ofdDir.getSysAbsPath();
        Path path = Paths.get(ofwTmp + pwd);
        return Files.exists(path) && Files.isDirectory(path);
    }


    /**
     * 打印工作目录 Print Work Directory
     * <p>
     * 路径最后如果是目录也不加 "/"
     *
     * @return 工作目录路径
     */
    public String pwd() {
        return pwd(this.workDir);
    }


    /**
     * 打印工作目录 Print Work Directory
     *
     * @param workDir 工作目录
     * @return 工作目录路径
     */
    public String pwd(List<String> workDir) {
        if (workDir.size() == 1) {
            return "/";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0, len = workDir.size(); i < len; i++) {
            String item = workDir.get(i);
            item = item.trim();
            if (item.isEmpty()) {
                continue;
            }
            sb.append(item);
            // 最后一个路径不加"/"
            if (!item.equals("/") && (i != len - 1)) {
                sb.append("/");
            }
        }
        return sb.toString();
    }


    /**
     * 根据路径获取获取对应的资源对象
     *
     * @param loc    路径地址
     * @param mapper 对象映射构造器
     * @param <R>    映射对象
     * @return 对象
     * @throws FileNotFoundException 文件不存在
     * @throws DocumentException     文件解析异常
     */
    public <R> R get(ST_Loc loc, Function<Element, R> mapper) throws FileNotFoundException, DocumentException {
        return get(loc.getLoc(), mapper);
    }

    /**
     * 根据路径获取获取对应的资源对象
     *
     * @param loc    路径地址
     * @param mapper 对象映射构造器
     * @param <R>    映射对象
     * @return 对象
     * @throws FileNotFoundException 文件不存在
     * @throws DocumentException     文件解析异常
     */
    public <R> R get(String loc, Function<Element, R> mapper) throws FileNotFoundException, DocumentException {
        if (loc == null || loc.trim().equals("")) {
            throw new FileNotFoundException("路径为空（loc）");
        }
        // 查询工作目录
        LinkedList<String> wd = new LinkedList<>(this.workDir);
        // 文件名称
        String fileName;
        int indexOf = loc.lastIndexOf('/');
        if (indexOf != -1) {
            // 切换工作目录
            this.cd(wd, loc.substring(0, indexOf + 1));
            fileName = loc.substring(indexOf + 1);
        } else {
            fileName = loc;
        }
        // 查找并获取文件所处路径
        VirtualContainer vc = getContainer(wd);
        Element element = vc.getObj(fileName);
        return mapper.apply(element);
    }




        /**
         * 获取路径下的文件
         *
         * @param stLoc 路径
         * @return 系统文件路径
         * @throws FileNotFoundException 文件或路径不存在
         */
    public Path getFile(ST_Loc stLoc) throws FileNotFoundException {
        String loc = stLoc.getLoc();
        if (loc == null || loc.trim().equals("")) {
            throw new FileNotFoundException("路径为空（loc）");
        }
        // 查询工作目录
        LinkedList<String> wd = new LinkedList<>(this.workDir);
        // 文件名称
        String fileName;
        int indexOf = loc.lastIndexOf('/');
        if (indexOf != -1) {
            // 切换工作目录
            this.cd(wd, loc.substring(0, indexOf + 1));
            fileName = loc.substring(indexOf + 1);
        } else {
            fileName = loc;
        }
        // 查找并获取文件所处路径
        VirtualContainer vc = getContainer(wd);
        return vc.getFile(fileName);
    }


    /**
     * 通过路径获取容器
     *
     * @param workDir 路径序列
     * @return 虚拟容器
     * @throws FileNotFoundException 路径不存在
     */
    public VirtualContainer getContainer(LinkedList<String> workDir) throws FileNotFoundException {
        VirtualContainer vc = ofdDir;
        for (String item : workDir) {
            if (item.equals("/")) {
                continue;
            } else if (item.startsWith("Doc_")) {
                vc = vc.getContainer(item, DocDir::new);
            } else if (item.equals("Signs")) {
                vc = vc.getContainer(item, SignsDir::new);
            } else if (item.startsWith("Sign_")) {
                vc = vc.getContainer(item, SignDir::new);
            } else if (item.equals("Pages")) {
                vc = vc.getContainer(item, PagesDir::new);
            } else if (item.startsWith("Page_")) {
                vc = vc.getContainer(item, PageDir::new);
            } else if (item.equals("Res")) {
                vc = vc.getContainer(item, ResDir::new);
            } else {
                vc = vc.getContainer(item, VirtualContainer::new);
            }
        }
        return vc;
    }

}
