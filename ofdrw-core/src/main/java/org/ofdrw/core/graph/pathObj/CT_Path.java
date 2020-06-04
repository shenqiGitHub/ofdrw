package org.ofdrw.core.graph.pathObj;

import org.dom4j.Element;
import org.ofdrw.core.basicStructure.pageObj.layer.block.PathObject;
import org.ofdrw.core.basicType.ST_ID;
import org.ofdrw.core.pageDescription.CT_GraphicUnit;
import org.ofdrw.core.pageDescription.clips.ClipAble;
import org.ofdrw.core.pageDescription.color.color.CT_Color;

/**
 * 图形对象
 * <p>
 * 图形对象具有一般图元的一切属性和行为特征。
 * <p>
 * 9.1 图形对象 图 46  表 35
 *
 * @author 权观宇
 * @since 2019-10-16 08:21:58
 */
public class CT_Path extends CT_GraphicUnit<CT_Path> implements ClipAble {

    public CT_Path(Element proxy) {
        super(proxy);
    }

    public CT_Path() {
        super("Path");
    }

    protected CT_Path(String name) {
        super(name);
    }

    /**
     * 构造路径对象
     *
     * @param id 对象ID
     * @return 对象
     */
    public PathObject toObj(ST_ID id) {
        this.setOFDName("PathObject");
        this.setObjID(id);
        return new PathObject(this);
    }

    /**
     * 【可选 属性】
     * 设置 图形是否被沟边
     *
     * @param stroke true - 沟边；false - 不勾边
     * @return this
     */
    public CT_Path setStroke(Boolean stroke) {
        if (stroke == null) {
            this.removeAttr("Stroke");
            return this;
        }
        this.addAttribute("Stroke", stroke.toString());
        return this;
    }

    /**
     * 【可选 属性】
     * 获取 图形是否被沟边
     *
     * @return true - 沟边；false - 不勾边
     */
    public Boolean getStroke() {
        String str = this.attributeValue("Stroke");
        if (str == null || str.trim().length() == 0) {
            return true;
        }
        return Boolean.parseBoolean(str);
    }

    /**
     * 【可选 属性】
     * 设置 图形是否被填充
     *
     * @param fill true - 填充； false - 不填充
     * @return this
     */
    public CT_Path setFill(Boolean fill) {
        if (fill == null) {
            this.removeAttr("Fill");
            return this;
        }
        this.addAttribute("Fill", fill.toString());
        return this;
    }

    /**
     * 【可选 属性】
     * 获取 图形是否被填充
     *
     * @return true - 填充； false - 不填充
     */
    public Boolean getFill() {
        String str = this.attributeValue("Fill");
        if (str == null || str.trim().length() == 0) {
            return false;
        }
        return Boolean.parseBoolean(str);
    }


    /**
     * 【可选 属性】
     * 设置  图形的填充规则
     * <p>
     * 当 Fill 属性存在时出现，可选值参考 {@link Rule}
     * <p>
     * 默认值为 NonZero
     *
     * @param rule 图形的填充规则
     * @return this
     */
    public CT_Path setRule(Rule rule) {
        if (rule == null) {
            this.removeAttr("Rule");
            return this;
        }
        this.addAttribute("Rule", rule.toString());
        return this;
    }

    /**
     * 【可选 属性】
     * 获取 图形的填充规则
     * <p>
     * 当 Fill 属性存在时出现，可选值参考 {@link Rule}
     * <p>
     * 默认值为 NonZero
     *
     * @return 图形的填充规则
     */
    public Rule getRule() {
        return Rule.getInstance(this.attributeValue("Rule"));
    }

    /**
     * 【可选】
     * 设置 沟边颜色
     * <p>
     * 默认为黑色
     *
     * @param strokeColor 沟边颜色，颜色定义请参考 8.3.2 基本颜色
     * @return this
     */
    public CT_Path setStrokeColor(CT_Color strokeColor) {
        if (strokeColor == null) {
            return this;
        }
        if (!(strokeColor instanceof StrokeColor)) {
            strokeColor.setOFDName("StrokeColor");
        }
        this.removeOFDElemByNames("StrokeColor");
        this.add(strokeColor);
        return this;
    }

    /**
     * 【可选】
     * 获取 沟边颜色
     * <p>
     * 默认为黑色
     *
     * @return 沟边颜色，null表示为黑色，颜色定义请参考 8.3.2 基本颜色
     */
    public StrokeColor getStrokeColor() {
        Element e = this.getOFDElement("StrokeColor");
        return e == null ? null : new StrokeColor(e);
    }

    /**
     * 【可选】
     * 设置 填充颜色
     * <p>
     * 默认为透明色
     *
     * @param fillColor 填充颜色，颜色定义请参考 8.3.2 基本颜色
     * @return this
     */
    public CT_Path setFillColor(CT_Color fillColor) {
        if (fillColor == null) {
            return this;
        }
        if (!(fillColor instanceof FillColor)) {
            fillColor.setOFDName("FillColor");
        }
        this.removeOFDElemByNames("FillColor");
        this.add(fillColor);
        return this;
    }

    /**
     * 【可选】
     * 获取 填充颜色
     * <p>
     * 默认为透明色
     *
     * @return 填充颜色，颜色定义请参考 8.3.2 基本颜色
     */
    public CT_Color getFillColor() {
        Element e = this.getOFDElement("FillColor");
        return e == null ? null : new FillColor(e);
    }

    /**
     * 【必选】
     * 设置 图形轮廓数据
     * <p>
     * 由一系列紧缩的操作符和操作数构成
     *
     * @param abbreviatedData 图形轮廓数据
     * @return this
     */
    public CT_Path setAbbreviatedData(AbbreviatedData abbreviatedData) {
        if (abbreviatedData == null) {
            return this;
        }
        this.removeOFDElemByNames("AbbreviatedData");
        this.add(abbreviatedData.flush());
        return this;
    }

    /**
     * 【必选】
     * 获取 图形轮廓数据
     * <p>
     * 由一系列紧缩的操作符和操作数构成
     *
     * @return 图形轮廓数据字符串
     */
    public String getAbbreviatedData() {
        Element e = this.getOFDElement("AbbreviatedData");
        return e == null ? null : e.getText();
    }

}
