package org.ofdrw.core.text.transform;

import org.junit.jupiter.api.Test;
import org.ofdrw.TestTool;
import org.ofdrw.core.basicType.ST_Array;
import org.ofdrw.core.text.CT_CGTransfrom;

public class CT_CGTransfromTest {

    public static CT_CGTransfrom cgTransfromCase(){
        return new CT_CGTransfrom()
                .setCodePosition(1)
                .setCodeCount(2)
                .setGlyphCount(2)
                .setGlyphs(new ST_Array(68, 74));
    }

    @Test
    public void gen() throws Exception {
        TestTool.genXml("CT_CGTransfrom", cgTransfromCase());
    }
}