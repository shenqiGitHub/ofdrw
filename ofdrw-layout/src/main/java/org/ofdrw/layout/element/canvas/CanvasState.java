package org.ofdrw.layout.element.canvas;

import org.ofdrw.core.basicType.ST_Array;

/**
 * 画布状态
 *
 * @author 权观宇
 * @since 2020-05-06 19:22:15
 */
public class CanvasState implements Cloneable {
    /**
     * 待裁剪区域构造工厂
     */
    ClipFactory clipFactory;

    /**
     * 描边RGB颜色
     * <p>
     * 默认黑色
     */
    int[] strokeColor = null;

    /**
     * 填充RGB颜色
     * <p>
     * 默认黑色
     */
    int[] fillColor = null;

    /**
     * 变换矩阵
     */
    ST_Array ctm = null;


    /**
     * 线宽度
     * <p>
     * 默认值 0.353 mm
     */
    double lineWidth = 0.353;

    /**
     * 绘制文字设置
     * <p>
     * 默认为宋体，字号为1
     */
    FontSetting font = null;


    /**
     * 透明值。必须介于 0.0（完全透明） 与 1.0（不透明） 之间。
     */
    Double globalAlpha = null;


    public CanvasState() {
    }

    @Override
    public CanvasState clone() {
        CanvasState that = new CanvasState();
        if (clipFactory != null) {
            that.clipFactory = clipFactory.clone();
        }
        if (strokeColor != null) {
            that.strokeColor = strokeColor.clone();
        }
        if (fillColor != null) {
            that.fillColor = fillColor.clone();
        }
        if (ctm != null) {
            that.ctm = ctm.clone();
        }
        that.lineWidth = lineWidth;
        if (font != null) {
            that.font = font.clone();
        }
        if (globalAlpha != null) {
            that.globalAlpha = globalAlpha;
        }
        return that;
    }
}
