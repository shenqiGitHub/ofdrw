package org.ofdrw.font;

/**
 * 字体名称
 *
 * @author 权观宇
 * @since 2020-03-18 20:42:45
 */
public enum FontName {

    /**
     * 思源黑体
     */
    NotoSans("NotoSansMonoCJKsc-Regular.otf"),
    /**
     * 思源黑体-粗体
     */
    NotoSansBold("NotoSansMonoCJKsc-Bold.otf"),

    /**
     * 思源宋体
     */
    NotoSerif("NotoSerifCJKsc-Regular.otf"),
    /**
     * 思源宋体-粗体
     */
    NotoSerifBold("NotoSerifCJKsc-Bold.otf"),

    /**
     * 宋体
     */
    SimSun(),
    /**
     * 黑体
     */
    SimHei(),
    /**
     * 微软雅黑
     */
    MSYahei(),
    /**
     * 楷体
     */
    KaiTi(),
    /**
     * 仿宋
     */
    FangSong(),

    /**
     * Times New Roman
     * <p>
     * 注意该字体只支持英文
     */
    TimesNewRoman();

    /**
     * 字体名称
     */
    private String fileName;

    FontName() {
    }

    FontName(String fileName) {
        this.fileName = fileName;
    }

    /**
     * 获取字字体文件名带后缀
     *
     * @return 字体文件名
     */
    public String getFilename() {
        return fileName;
    }
}
