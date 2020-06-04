package org.ofdrw.sign.verify.container;

import org.junit.jupiter.api.Test;
import org.ofdrw.gm.ses.parse.SESChainData;
import org.ofdrw.reader.OFDReader;
import org.ofdrw.sign.verify.OFDValidator;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author 权观宇
 * @since 2020-04-22 23:37:16
 */
class SESV1ValidateContainerTest {
    @Test
    void validate() throws IOException, GeneralSecurityException {
        Path src = Paths.get("/Users/qishen/Downloads/盖章ofd/signpage 01.ofd");
//        Path src = Paths.get("C:\\Users\\qishen\\Desktop\\CommandLineHelp.ofd");

        try (OFDReader reader = new OFDReader(src);
            OFDValidator validator = new OFDValidator(reader)) {
//            validator.setValidator(new SESV1ValidateContainer());
            List<SESChainData> signChainData = validator.getSignChainData();
            validator.exeValidate();
            System.out.println(">> 验证通过");
        }
    }
}