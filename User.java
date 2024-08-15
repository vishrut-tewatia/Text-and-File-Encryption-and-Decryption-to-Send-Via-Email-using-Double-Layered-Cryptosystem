import javax.swing.*;
import java.awt.*;
import javax.swing.ImageIcon;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.spec.SecretKeySpec;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class User implements ActionListener {
  private static JTextField location;
  private static JTextField location2;
  private static JTextArea msg;
  private static JTextArea dmsg;
  private static JButton encrypt;
  private static JButton decrypt;
  private static JButton encrypt1;
  private static JButton decrypt1;
  private static JRadioButton highsec;
  private static JRadioButton lowsec;
  private static ButtonGroup G1;
  private static JButton imagebutton;
  private RSAText textencrypt;
  private RSAFile fileencrypt;
  private static int seclevel = 0;
  private static String dir;

  public void textencryption() {
    this.textencrypt = new RSAText();
    this.textencrypt.generatekey();
    try {
      this.textencrypt.storekeys();
    } catch (Exception e0) {
      // TODO: handle exception
    }
  }

  public void fileencryption() {
    this.fileencrypt = new RSAFile();
    this.fileencrypt.generatekey();
    try {
      this.fileencrypt.storekeys();
    } catch (Exception e0) {
      // TODO: handle exception
    }
  }

  public static void main(String[] args) {
    dir = System.getProperty("user.dir");
    JPanel panel = new JPanel();
    JPanel panel1 = new JPanel();
    JFrame frame = new JFrame(
        "B.Tech Project : Text and File Encryption and Decryption to send via email using Double Layered Cryptosystem");
    frame.setSize(800, 500);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setLayout(null);

    panel.setBounds(0, 0, 400, 500);
    panel.setLayout(null);
    panel.setBackground(new Color(180, 180, 180));
    frame.add(panel);

    panel1.setBounds(400, 0, 400, 500);
    panel1.setLayout(null);
    panel1.setBackground(new Color(170, 170, 170));
    frame.add(panel1);

    JLabel head = new JLabel("Text Encryption for Email Body");
    head.setFont(new Font("Myriad Pro", Font.PLAIN, 17));
    head.setBounds(50, 30, 400, 25);
    panel.add(head);

    JLabel plaintext = new JLabel("Input Text : ");
    plaintext.setBounds(10, 70, 80, 25);
    panel.add(plaintext);

    msg = new JTextArea(5, 20);
    msg.setLineWrap(true);
    JScrollPane scrollPane = new JScrollPane(msg);
    scrollPane.setBounds(120, 70, 165, 100);
    scrollPane.setSize(250, 150);
    panel.add(scrollPane, BorderLayout.CENTER);

    encrypt = new JButton("Encrypt");
    encrypt.setBounds(120, 230, 80, 25);
    encrypt.addActionListener(new User());
    panel.add(encrypt);

    decrypt = new JButton("Decrypt");
    decrypt.setBounds(280, 230, 80, 25);
    decrypt.addActionListener(new User());
    panel.add(decrypt);

    JLabel ciphertext = new JLabel("Output Text : ");
    ciphertext.setBounds(10, 265, 100, 25);
    panel.add(ciphertext);

    dmsg = new JTextArea(5, 20);
    dmsg.setLineWrap(true);
    JScrollPane scrollPane1 = new JScrollPane(dmsg);
    scrollPane1.setBounds(120, 265, 165, 100);
    scrollPane1.setSize(250, 150);
    panel.add(scrollPane1, BorderLayout.CENTER);

    // panel1 things

    JLabel head1 = new JLabel("File Encryption for Email Attachment");
    head1.setFont(new Font("Myriad Pro", Font.PLAIN, 17));
    head1.setBounds(50, 30, 400, 25);
    panel1.add(head1);

    imagebutton = new JButton("Input File Location");
    imagebutton.setBounds(100, 100, 200, 25);
    imagebutton.addActionListener(new User());
    panel1.add(imagebutton);

    location = new JTextField();
    location.setBounds(20, 140, 360, 25);
    panel1.add(location);

    G1 = new ButtonGroup();

    highsec = new JRadioButton("High Security");
    highsec.setBounds(40, 180, 200, 25);
    highsec.addActionListener(new User());
    panel1.add(highsec);

    lowsec = new JRadioButton("Low Security");
    lowsec.setBounds(240, 180, 200, 25);
    lowsec.addActionListener(new User());
    panel1.add(lowsec);

    G1.add(highsec);
    G1.add(lowsec);

    encrypt1 = new JButton("Encrypt");
    encrypt1.setBounds(40, 230, 80, 25);
    encrypt1.addActionListener(new User());
    panel1.add(encrypt1);

    decrypt1 = new JButton("Decrypt");
    decrypt1.setBounds(240, 230, 80, 25);
    decrypt1.addActionListener(new User());
    panel1.add(decrypt1);

    JLabel out = new JLabel("Output File Location:");
    out.setBounds(130, 280, 200, 25);
    panel1.add(out);

    location2 = new JTextField();
    location2.setBounds(20, 320, 360, 25);
    panel1.add(location2);

    JLabel labelimage = new JLabel();
    labelimage.setBounds(20, 370, 75, 75);
    ImageIcon dtu = new ImageIcon("/Users/sarth/Desktop/DTU FINAL B TECH PROJECT/BTP_Report_latex/DTU.png");
    Image img = dtu.getImage();
    Image scaled = img.getScaledInstance(labelimage.getWidth(), labelimage.getHeight(), Image.SCALE_SMOOTH);
    ImageIcon scaledtu = new ImageIcon(scaled);
    labelimage.setIcon(scaledtu);
    panel1.add(labelimage);

    JLabel dep = new JLabel("Department of Applied Mathematics");
    dep.setBounds(135, 370, 300, 50);
    panel1.add(dep);
    JLabel campus = new JLabel("DELHI TECHNOLOGICAL UNIVERSITY(Formerly DCE)");
    campus.setBounds(100, 390, 350, 50);
    panel1.add(campus);

    frame.setVisible(true);
  }

  public void actionPerformed(ActionEvent e) {
    long startTime = System.nanoTime();

    // for Text Encryption
    if (e.getSource() == encrypt) {
      String text = msg.getText();
      this.textencryption();
      try {
        dmsg.setText(this.textencrypt.encryption(text));
      } catch (Exception ea) {
        // TODO: handle exception
      }
      System.out.println("Encrypt button clicked");
    }
    if (e.getSource() == decrypt) {
      String text = msg.getText();
      JFileChooser choosefile = new JFileChooser();
      choosefile.setMultiSelectionEnabled(true);
      choosefile.showOpenDialog(null);
      File[] privatefile = choosefile.getSelectedFiles();
      if (privatefile == null) {
        return;
      }
      String keyfile = privatefile[1].getAbsolutePath();
      String cipherfile = privatefile[0].getAbsolutePath();
      try {
        RSAText textdecrypt = new RSAText();
        dmsg.setText(textdecrypt.decryption(text, cipherfile, keyfile));
      } catch (Exception e2) {
        // TODO: handle exception
      }
      System.out.println("Decrypt button clicked");
    }

    // For file encryption
    if (e.getSource() == imagebutton) {
      JFileChooser chooser = new JFileChooser();
      chooser.showOpenDialog(null);
      File f = chooser.getSelectedFile();
      if (f == null) {
        return;
      }
      String filename = f.getAbsolutePath();
      location.setText(filename);
    }

    if (e.getSource() == lowsec) {
      System.out.println("Low Security");
      seclevel = 1;
    }
    if (e.getSource() == highsec) {
      System.out.println("High Security");
      seclevel = 2;
    }
    if (e.getSource() == encrypt1 && seclevel == 1) {

      String extension = "";
      String path = "";
      SecretKey a = null;

      // path,extension and file name
      int index = location.getText().lastIndexOf('.');
      if (index > 0) {
        extension = location.getText().substring(index + 1);
      }
      index = location.getText().lastIndexOf('/');
      if (index > 0) {
        path = location.getText().substring(0, index + 1);
      }
      AESLow aesfile = new AESLow();
      File toencrypt = new File(location.getText());
      File encrypted = new File(path + "encrypted." + extension);
      // File decrypted = new File(path+"decrypted."+extension);
      try {
        a = aesfile.generateKey(256);
      } catch (Exception e3) {
        // TODO: handle exception
      }
      IvParameterSpec b = aesfile.generateIv();

      try {
        aesfile.encryptFile(a, b, toencrypt, encrypted);
        // aesfile.decryptFile(a, b, encrypted, decrypted);
      } catch (Exception e4) {
        // TODO: handle exception
      }
      location2.setText(path + "encrypted." + extension);

    }
    if (e.getSource() == decrypt1 && seclevel == 1) {
      JFileChooser choosefile = new JFileChooser();
      choosefile.setMultiSelectionEnabled(true);
      choosefile.showOpenDialog(null);
      File[] privatefile = choosefile.getSelectedFiles();
      if (privatefile == null) {
        return;
      }
      String keyfile = "";
      keyfile = privatefile[1].getAbsolutePath();
      String ivfile = "";
      ivfile = privatefile[0].getAbsolutePath();

      String extension = "";
      String path = "";
      SecretKey a = null;
      IvParameterSpec b = null;

      // path,extension and file name
      int index = location.getText().lastIndexOf('.');
      if (index > 0) {
        extension = location.getText().substring(index + 1);
      }
      index = location.getText().lastIndexOf('/');
      if (index > 0) {
        path = location.getText().substring(0, index + 1);
      }
      AESLow aesfile = new AESLow();
      File encrypted = new File(location.getText());
      File decrypted = new File(path + "decrypted." + extension);
      location2.setText(path + "decrypted." + extension);

      try {
        byte[] keyb = Files.readAllBytes(Paths.get(keyfile));
        SecretKeySpec skey = new SecretKeySpec(keyb, "AES");
        a = skey;
      } catch (Exception eha1) {
        // TODO: handle exception
      }
      try {
        byte[] keyiv = Files.readAllBytes(Paths.get(ivfile));
        b = new IvParameterSpec(keyiv);
      } catch (Exception eha2) {
        // TODO: handle exception
      }
      try {
        aesfile.decryptFile(a, b, encrypted, decrypted);
      } catch (Exception eha3) {
        // TODO: handle exception
      }
    }

    if (e.getSource() == encrypt1 && seclevel == 2) {

      String extension = "";
      String path = "";
      SecretKey a = null;

      // path,extension and file name
      int index = location.getText().lastIndexOf('.');
      if (index > 0) {
        extension = location.getText().substring(index + 1);
      }
      index = location.getText().lastIndexOf('/');
      if (index > 0) {
        path = location.getText().substring(0, index + 1);
      }

      AESLow aesfile = new AESLow();
      File toencrypt = new File(location.getText());
      File encrypted = new File(path + "encrypted." + extension);
      location2.setText(path + "encrypted." + extension);

      try {
        a = aesfile.generateKey(256);
      } catch (Exception e3) {
        // TODO: handle exception
      }
      IvParameterSpec b = aesfile.generateIv();

      try {
        aesfile.encryptFile(a, b, toencrypt, encrypted);
      } catch (Exception e4) {
        // TODO: handle exception
      }
      this.fileencryption();
      try {
        this.fileencrypt.encryption(dir + "/Fileaes.key");
      } catch (Exception ea) {
        // TODO: handle exception
      }
      System.out.println("Encrypt button clicked");

    }
    if (e.getSource() == decrypt1 && seclevel == 2) {
      SecretKey a = null;
      JFileChooser choosefile = new JFileChooser();
      choosefile.setMultiSelectionEnabled(true);
      choosefile.showOpenDialog(null);
      File[] privatefile = choosefile.getSelectedFiles();
      if (privatefile == null) {
        return;
      }
      String keyfile = "";
      keyfile = privatefile[1].getAbsolutePath();
      String ivfile = "";
      ivfile = privatefile[0].getAbsolutePath();
      String rsakeyfile = "";
      rsakeyfile = privatefile[2].getAbsolutePath();

      try {
        RSAFile filedecrypt = new RSAFile();
        a = filedecrypt.decryption(keyfile, rsakeyfile);
      } catch (Exception e2) {
        // TODO: handle exception
      }

      String extension = "";
      String path = "";
      IvParameterSpec b = null;

      // path,extension and file name
      int index = location.getText().lastIndexOf('.');
      if (index > 0) {
        extension = location.getText().substring(index + 1);
      }
      index = location.getText().lastIndexOf('/');
      if (index > 0) {
        path = location.getText().substring(0, index + 1);
      }
      AESLow aesfile = new AESLow();
      File encrypted = new File(location.getText());
      File decrypted = new File(path + "decrypted." + extension);
      location2.setText(path + "decrypted." + extension);

      try {
        byte[] keyiv = Files.readAllBytes(Paths.get(ivfile));
        b = new IvParameterSpec(keyiv);
      } catch (Exception eha2) {
        // TODO: handle exception
      }
      try {
        aesfile.decryptFile(a, b, encrypted, decrypted);
      } catch (Exception eha3) {
        // TODO: handle exception
      }
    }
    long endTime = System.nanoTime();
    long timeElapsed = endTime - startTime;
    System.out.println("Execution time in milliseconds: " + timeElapsed / 1000000);

  }
}
