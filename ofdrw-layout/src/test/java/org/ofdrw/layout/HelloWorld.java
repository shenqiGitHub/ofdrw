package org.ofdrw.layout;

import org.ofdrw.layout.element.Paragraph;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @author 权观宇
 * @since 2020-03-26 19:21:17
 */
public class HelloWorld {

    public static void main(String[] args) throws IOException {
        Path path = Paths.get("ofdrw-layout/target/helloworld.ofd").toAbsolutePath();
        System.out.println(path.toString());
        try (OFDDoc ofdDoc = new OFDDoc(path)) {
            Paragraph p = new Paragraph("你好呀，OFD Reader&Writer！");
            ofdDoc.add(p);
        }
        System.out.println("生成文档位置: " + path.toAbsolutePath());
    }
}
