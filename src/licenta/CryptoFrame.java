package licenta;



import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.LayoutManager;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.naming.directory.NoSuchAttributeException;
import javax.swing.*;
import javax.swing.filechooser.FileSystemView;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;

public class CryptoFrame extends JFrame {

    final DefaultComboBoxModel<String> model, model3;
    private JComboBox<String> comboOperationType, comboEncryptionType, comboResourceType;
    private Container contentPane;
    private JLabel jLabelHelper, jLabelAlg, jLabelKeyLength, jLabelSymmetricKeyAlg, jLabelFileKey;
    private JTextField jTFAlgorithm, JTFKeyLength, JTFHelper, JTFSymmetricKeyAlg, JTFFileKey;
    private JButton sendEmail, performCrypto, selectFile;
    private JFileChooser JFileChooser;
    private GridBagConstraints grid;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private int getKeyfromComp;
    private CryptoFrame cf;
    private String encrypted;
    private String decrypted;
    private byte[] encryptedBytes;
    private byte[] decryptedBytes;


    public CryptoFrame() {
        // TODO Auto-generated constructor stub
        contentPane = this.getContentPane();
        setTitle("Fereastra Cripto");
        setSize(400, 400);
        setLocation(new Point(1200, 100));
        setLayout(new FlowLayout());
        setResizable(false);
        model = new DefaultComboBoxModel<>();
        model3 = new DefaultComboBoxModel<>();

        initComponents();
        contentPane.add(comboOperationType);
        contentPane.add(comboEncryptionType);
        contentPane.add(comboResourceType);
        contentPane.add(jLabelHelper);
        contentPane.add(JTFHelper);
        contentPane.add(jLabelAlg);
        contentPane.add(jTFAlgorithm);
        contentPane.add(jLabelKeyLength);
        contentPane.add(JTFKeyLength);
        contentPane.add(jLabelSymmetricKeyAlg);
        contentPane.add(JTFSymmetricKeyAlg);
        contentPane.add(jLabelFileKey);
        contentPane.add(JTFFileKey);
        contentPane.add(selectFile);
        contentPane.add(performCrypto);
        contentPane.add(sendEmail);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

    }

    private void initComponents() {
        initComboBoxes();

        this.jLabelHelper = new JLabel();
        this.jLabelAlg = new JLabel();
        this.jLabelKeyLength = new JLabel();
        this.jLabelFileKey = new JLabel();

        this.JTFHelper = new JTextField(10);
        this.jTFAlgorithm = new JTextField(5);
        this.JTFFileKey = new JTextField(20);
        this.JTFKeyLength = new JTextField(4);
        this.jLabelSymmetricKeyAlg = new JLabel();
        this.JTFSymmetricKeyAlg = new JTextField(4);

        this.JFileChooser = new JFileChooser();

        this.selectFile = new JButton();
        this.sendEmail = new JButton();
        this.performCrypto = new JButton();

        this.jLabelHelper.setVisible(false);
        this.jLabelAlg.setVisible(false);
        this.jLabelKeyLength.setVisible(false);
        this.jLabelSymmetricKeyAlg.setVisible(false);
        this.JTFHelper.setVisible(false);
        this.jTFAlgorithm.setVisible(false);
        this.JTFKeyLength.setVisible(false);
        this.JTFSymmetricKeyAlg.setVisible(false);
        this.JFileChooser.setVisible(false);
        this.jLabelFileKey.setVisible(false);
        this.JTFFileKey.setVisible(false);
        this.selectFile.setVisible(false);
        this.performCrypto.setVisible(false);
        this.sendEmail.setVisible(false);
    }

    private void initComboBoxes() {
        this.comboEncryptionType = new JComboBox<>();
        this.comboResourceType = new JComboBox<>();

        this.comboEncryptionType.setVisible(false);
        this.comboResourceType.setVisible(false);

        String[] criptableElements = {" ", "Criptare Asimetrica", "Criptare Simetrica", "Comparatie Timpi"};
        this.comboOperationType = new JComboBox<String>(criptableElements);
        this.comboOperationType.setName("comboFirst");
        this.comboOperationType.setSelectedIndex(0);

        comboOperationType.addItemListener(getComboOperationTypeListner()); //simetric, asimetric, comparatie
        comboEncryptionType.addItemListener(getComboEncryptionTypeListner()); //criptare, decriptare
        comboResourceType.addActionListener(getComboResourceTypeListner()); //text, fisier, imagine
    }

    private ItemListener getComboOperationTypeListner() {
        String[] encryptType = {" ", "Criptare", "Decriptare"};
        return new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent ie) {
                comboEncryptionType.setModel(model);
                model.removeAllElements();

                if (ie != null && ie.getSource() != null && comboOperationType.getSelectedIndex() == 1
                        || comboOperationType.getSelectedIndex() == 2 || comboOperationType.getSelectedIndex() == 3) {

                    if (ie.getStateChange() == ItemEvent.SELECTED) {
                        for (String s : encryptType) {
                            model.addElement(s);
                            comboEncryptionType.setVisible(true);
                            comboEncryptionType.setSelectedIndex(0);
                        }
                    }
                } else {
                    comboEncryptionType.setVisible(false);
                }
            }
        };
    }

    private ItemListener getComboEncryptionTypeListner() {
        String[] type = {" ", "Text", "Fisier", "Imagine"};
        return new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent ie) {
                // TODO Auto-generated method stub
                comboResourceType.setModel(model3);
                model3.removeAllElements();
                if (comboEncryptionType.isShowing() && ie != null && ie.getSource() != null
                        && comboEncryptionType.getSelectedIndex() == 1 || comboEncryptionType.getSelectedIndex() == 2) {
                    if (ie.getStateChange() == ItemEvent.SELECTED) {
                        for (String s : type) {
                            model3.addElement(s);
                            comboResourceType.setVisible(true);
                        }
                    }
                } else {
                    comboResourceType.setVisible(false);
                }
            }
        };
    }

    private ActionListener getComboResourceTypeListner() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // encrypt asymmetric text
                if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 1
                        && comboEncryptionType.getSelectedIndex() == 1 && comboResourceType.getSelectedIndex() == 1) {
                    changeStateCryptoElements(true, true, false, true, false);
                    clearCryptoTextFields();

                    // add label for text inserting
                    jLabelHelper.setText("Introduceti textul: ");

                    // add TF for inserting plainText
                    JTFHelper.setMaximumSize(new Dimension(100, 28));
                    JTFHelper.setPreferredSize(new Dimension(100, 28));

                    // add label for setting the algorithm
                    jLabelAlg.setText("Introduceti algoritmul de criptare: ");

                    // add TF for algorithm insertion
                    jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                    jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                    // add label for keylength
                    jLabelKeyLength.setText("Introduceti lungimea cheii: ");

                    // add TF for key length
                    jTFAlgorithm.setMaximumSize(new Dimension(150, 80));
                    jTFAlgorithm.setPreferredSize(new Dimension(150, 80));

                    // perform asymmetric encryption..
                    performCrypto.setText("Criptare");


                    removeAllActionListenersFromButton(performCrypto);
                    performCrypto.addActionListener(getPerformAssymetricListener());
                }


                //decrypt asymmetric text
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 1
                            && comboEncryptionType.getSelectedIndex() == 2 && comboResourceType.getSelectedIndex() == 1) {
                        changeStateCryptoElements(true, true, false, false, false);
                        clearCryptoTextFields();

                        /* //add label for text inserting
                        jLabelHelper.setText("Introduceti textul: ");
                        // add TF for inserting plainText
                        JTFHelper.setMaximumSize(new Dimension(100, 28));
                        JTFHelper.setPreferredSize(new Dimension(100, 28)); */
                        // add label for setting the algorithm
                        jLabelAlg.setText("Introduceti algoritmul de decriptare: ");

                        // add TF for algorithm insertion
                        jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                        jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                        // add label for keylength
                        jLabelKeyLength.setText("Introduceti lungimea cheii: ");

                        // add TF for key length
                        jTFAlgorithm.setMaximumSize(new Dimension(150, 80));
                        jTFAlgorithm.setPreferredSize(new Dimension(150, 80));

                        // perform asymmetric decryption..
                        performCrypto.setText("Decriptare");
                        removeAllActionListenersFromButton(performCrypto);
                        performCrypto.addActionListener(getPerformAsymmetricDecryptionListener());

                    }

                // encrypt asymmetric file
              else  if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 1
                        && comboEncryptionType.getSelectedIndex() == 1 && comboResourceType.getSelectedIndex() == 2) {
                    changeStateCryptoElements(true, true, false, false, true);
                    clearCryptoTextFields();


                    JTFFileKey.setVisible(false);
                    jLabelFileKey.setVisible(false);

                    // add label for setting the algorithm
                    jLabelAlg.setText("Introduceti algoritmul de criptare: ");

                    // add TF for algorithm insertion
                    jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                    jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                    // add label for keylength
                    jLabelKeyLength.setText("Introduceti lungimea cheii: ");

                    // add TF for key length
                    jTFAlgorithm.setMaximumSize(new Dimension(150, 80));
                    jTFAlgorithm.setPreferredSize(new Dimension(150, 80));

                    //add file chooser for choosing the file
                    createSelectFileButton();

                    // perform asymmetric file encryption..
                    performCrypto.setText("Criptare");


                    removeAllActionListenersFromButton(performCrypto);
                    performCrypto.addActionListener(getPerformAsymmetricFileEncryption());


                }

                // decrypt asymmetric file
               else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 1
                        && comboEncryptionType.getSelectedIndex() == 2 && comboResourceType.getSelectedIndex() == 2) {
                    changeStateCryptoElements(true, true, false, false, true);
                    clearCryptoTextFields();


                    JTFFileKey.setVisible(false);
                    jLabelFileKey.setVisible(false);

                    // add label for setting the algorithm
                    jLabelAlg.setText("Introduceti algoritmul de decriptare: ");

                    // add TF for algorithm insertion
                    jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                    jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                    // add label for keylength
                    jLabelKeyLength.setText("Introduceti lungimea cheii: ");

                    // add TF for key length
                    jTFAlgorithm.setMaximumSize(new Dimension(150, 80));
                    jTFAlgorithm.setPreferredSize(new Dimension(150, 80));

                    //add file chooser for choosing the file
                    createSelectFileButton();

                    // perform asymmetric file decryption..
                    performCrypto.setText("Decriptare");


                    removeAllActionListenersFromButton(performCrypto);
                    performCrypto.addActionListener(getPerformAsymmetricFileDecryption());


                }

                // encrypt symmetric text
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 2
                        && comboEncryptionType.getSelectedIndex() == 1 && comboResourceType.getSelectedIndex() == 1) {
                    changeStateCryptoElements(true, false, true, true, false);
                    clearCryptoTextFields();

                    // add label for text inserting
                    jLabelHelper.setText("Introduceti textul: ");

                    // add TF for inserting plainText
                    JTFHelper.setMaximumSize(new Dimension(100, 28));
                    JTFHelper.setPreferredSize(new Dimension(100, 28));

                    // add label for setting the algorithm
                    jLabelAlg.setText("Introduceti algoritmul de criptare: ");

                    // add TF for algorithm insertion
                    jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                    jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                    //add label for symmetric key algorithm
                    jLabelSymmetricKeyAlg.setText("Introduceti algoritmul cheii: ");

                    //add TF for symmetric key algorithm
                    JTFSymmetricKeyAlg.setMaximumSize(new Dimension(100, 28));
                    JTFSymmetricKeyAlg.setPreferredSize(new Dimension(100, 28));

                    // perform symmetric encryption..
                    performCrypto.setText("Criptare");


                    removeAllActionListenersFromButton(performCrypto);
                    performCrypto.addActionListener(getPerformSymmetricListener());
                }


                    //decrypt symmetric text
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 2
                        &&comboEncryptionType.getSelectedIndex() == 2 && comboResourceType.getSelectedIndex() == 1) {

                        changeStateCryptoElements(true, false, true, false, false);
                        clearCryptoTextFields();

                       /* // add label for text inserting
                        jLabelHelper.setText("Introduceti textul: ");
                        // add TF for inserting plainText
                        JTFHelper.setMaximumSize(new Dimension(100, 28));
                        JTFHelper.setPreferredSize(new Dimension(100, 28)); */
                        // add label for setting the algorithm
                        jLabelAlg.setText("Introduceti algoritmul de decriptare: ");

                        // add TF for algorithm insertion
                        jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                        jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                        //add label for setting key alg
                        jLabelSymmetricKeyAlg.setText("Introduceti algoritmul cheii: ");

                        //add TF for key algorithm insertion
                        JTFSymmetricKeyAlg.setMaximumSize(new Dimension(100, 28));
                        JTFSymmetricKeyAlg.setPreferredSize(new Dimension(100, 28));


                        // perform symmetric decryption..
                        performCrypto.setText("Decriptare");
                        removeAllActionListenersFromButton(performCrypto);
                        performCrypto.addActionListener(getPerformSymmetricDecryptionListener());


                    }

                //encrypt file symmetric
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 2
                        && comboEncryptionType.getSelectedIndex() == 1 && comboResourceType.getSelectedIndex() == 2) {
                        clearCryptoTextFields();
                        changeStateCryptoElements(true, false, true, false, true);

                        // add label for setting the algorithm
                        jLabelAlg.setText("Introduceti algoritmul de criptare: ");

                        // add TF for algorithm insertion
                        jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                        jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                        //add label for setting key alg
                        jLabelSymmetricKeyAlg.setText("Introduceti algoritmul cheii: ");

                        //add TF for key algorithm insertion
                        JTFSymmetricKeyAlg.setMaximumSize(new Dimension(100, 28));
                        JTFSymmetricKeyAlg.setPreferredSize(new Dimension(100, 28));

                        //add label for setting key value
                        jLabelFileKey.setText("Introduceti minim 16 caractere pentru cheie: ");

                        //add TF for key algorithm insertion
                        JTFFileKey.setMaximumSize(new Dimension(100, 28));
                        JTFFileKey.setPreferredSize(new Dimension(100, 28));

                        //add file chooser for choosing the file
                         createSelectFileButton();


                        // perform symmetric file encryption..
                        performCrypto.setText("Criptare");
                        removeAllActionListenersFromButton(performCrypto);
                        performCrypto.addActionListener(getPerformSymmetricFileEncryption());


                    }


                //decrypt file symmetric
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 2
                         && comboEncryptionType.getSelectedIndex() == 2 && comboResourceType.getSelectedIndex() == 2) {
                        clearCryptoTextFields();
                        changeStateCryptoElements(true, false, true, false, true);

                        // add label for setting the algorithm
                        jLabelAlg.setText("Introduceti algoritmul de decriptare: ");

                        // add TF for algorithm insertion
                        jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                        jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                        //add label for setting key alg
                        jLabelSymmetricKeyAlg.setText("Introduceti algoritmul cheii: ");

                        //add TF for key algorithm insertion
                        JTFSymmetricKeyAlg.setMaximumSize(new Dimension(100, 28));
                        JTFSymmetricKeyAlg.setPreferredSize(new Dimension(100, 28));

                        //add label for setting key value
                        jLabelFileKey.setText("Introduceti minim 16 caractere pentru cheie: ");

                        //add TF for key algorithm insertion
                        JTFFileKey.setMaximumSize(new Dimension(100, 28));
                        JTFFileKey.setPreferredSize(new Dimension(100, 28));

                        //add file chooser for choosing the file
                        createSelectFileButton();


                        // perform symmetric file decryption..
                        performCrypto.setText("Decriptare");
                        removeAllActionListenersFromButton(performCrypto);
                        performCrypto.addActionListener(getPerformSymmetricFileDecryption());

                }
                        //symmetric image encryption
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 2
                        && comboEncryptionType.getSelectedIndex() == 1 && comboResourceType.getSelectedIndex() == 3) {
                    clearCryptoTextFields();
                    changeStateCryptoElements(true, false, true, false, true);

                    // add label for setting the algorithm
                    jLabelAlg.setText("Introduceti algoritmul de criptare: ");

                    // add TF for algorithm insertion
                    jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                    jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                    //add label for setting key alg
                    jLabelSymmetricKeyAlg.setText("Introduceti algoritmul cheii: ");

                    //add TF for key algorithm insertion
                    JTFSymmetricKeyAlg.setMaximumSize(new Dimension(100, 28));
                    JTFSymmetricKeyAlg.setPreferredSize(new Dimension(100, 28));

                    //add label for setting key value
                    jLabelFileKey.setVisible(false);
                    JTFFileKey.setVisible(false);

                    //add TF for key algorithm insertion
                    JTFFileKey.setMaximumSize(new Dimension(100, 28));
                    JTFFileKey.setPreferredSize(new Dimension(100, 28));

                    //add file chooser for choosing the file
                    createSelectFileButton();


                    // perform symmetric image encryption..
                    performCrypto.setText("Criptare");
                    removeAllActionListenersFromButton(performCrypto);
                    performCrypto.addActionListener(getPerformSymmetricImgEncryption());



                }
                    //symmetric img decryption
                else if (comboResourceType.isShowing() && e.getSource() != null && comboOperationType.getSelectedIndex() == 2
                        && comboEncryptionType.getSelectedIndex() == 2 && comboResourceType.getSelectedIndex() == 3) {
                    clearCryptoTextFields();
                    changeStateCryptoElements(true, false, true, false, true);

                    // add label for setting the algorithm
                    jLabelAlg.setText("Introduceti algoritmul de criptare: ");

                    // add TF for algorithm insertion
                    jTFAlgorithm.setMaximumSize(new Dimension(100, 28));
                    jTFAlgorithm.setPreferredSize(new Dimension(100, 28));

                    //add label for setting key alg
                    jLabelSymmetricKeyAlg.setText("Introduceti algoritmul cheii: ");

                    //add TF for key algorithm insertion
                    JTFSymmetricKeyAlg.setMaximumSize(new Dimension(100, 28));
                    JTFSymmetricKeyAlg.setPreferredSize(new Dimension(100, 28));

                    //add label for setting key value
                    jLabelFileKey.setVisible(false);
                    JTFFileKey.setVisible(false);

                    //add TF for key algorithm insertion
                    JTFFileKey.setMaximumSize(new Dimension(100, 28));
                    JTFFileKey.setPreferredSize(new Dimension(100, 28));

                    //add file chooser for choosing the file
                  //  createSelectFileButton();


                    // perform symmetric image decryption..
                    performCrypto.setText("Decriptare");
                    removeAllActionListenersFromButton(performCrypto);
                    performCrypto.addActionListener(getPerformSymmetricImgDecryption());

                }



                else {

                    changeStateCryptoElements(false, false, false, false, false);
                    clearCryptoTextFields();
                }

            }
        };

    }

    private ActionListener getPerformAssymetricListener() {
        return new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if (JTFKeyLength.getText() != null && JTFKeyLength.getText() != " "
                        && JTFKeyLength.getText().length() != 0 && JTFHelper.getText() != null
                        && JTFHelper.getText() != " " && JTFHelper.getText().length() != 0
                        && jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0) {

                    try {
                        AsymmetricCrypto ac = new AsymmetricCrypto(jTFAlgorithm.getText());
                        encrypted = ac.encryptText(JTFHelper.getText());
                        File file = new File("KeyPair/encrypted_text_asymmmetric.txt");
                        FileWriter fw = new FileWriter(file);
                        BufferedWriter bw = new BufferedWriter(fw);
                        if (file.exists()) {
                            file.delete();
                            file.createNewFile();
                            bw.write(encrypted);
                            bw.close();
                        }

                    } catch (Exception e2) {
                        // TODO Auto-generated catch block
                        e2.printStackTrace();
                    }

                    System.out.println("Criptarea a fost facuta cu succes !");
                    JOptionPane.showMessageDialog(cf, encrypted, "Rezultat criptare", JOptionPane.INFORMATION_MESSAGE);

                    createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare criptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
    }

    // crapa la decriptare. to be investigated
    private ActionListener getPerformAsymmetricDecryptionListener() {
        return new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if (JTFKeyLength.getText() != null && JTFKeyLength.getText() != " "
                        && JTFKeyLength.getText().length() != 0
                        && jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0) {


                    try {
                        AsymmetricCrypto ac = new AsymmetricCrypto(jTFAlgorithm.getText());
                        int i = 0;
                        byte byteVal = 0;
                        FileInputStream fis = new FileInputStream(new File("KeyPair/encrypted_text_asymmmetric.txt"));
                        while ((i = fis.read()) >= 0) {
                            byteVal = (byte) i;
                        }
                        //byte [] fromFile = ac.getFileAsBytes(new File ("KeyPair/encrypted_text.txt"));
                        decrypted = ac.decryptText(String.valueOf(byteVal));
                        System.out.println("Textul decriptat este: " + decrypted);

                    } catch (Exception e2) {
                        // TODO Auto-generated catch block
                        e2.printStackTrace();
                    }

                    System.out.println("Decriptarea a fost facuta cu succes !");
                    JOptionPane.showMessageDialog(cf, decrypted, "Rezultat decriptare", JOptionPane.INFORMATION_MESSAGE);

                    createSendEmailButton("carolinaangelica26@gmail.com", decrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare decriptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }

            }
        };

    }

    private ActionListener getPerformAsymmetricFileEncryption () {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {

                if (JTFKeyLength.getText() != null && JTFKeyLength.getText() != " "
                        && JTFKeyLength.getText().length() != 0 && jTFAlgorithm.getText() != null
                        && jTFAlgorithm.getText() != " " && jTFAlgorithm.getText().length() != 0) {

                    try {
                        AsymmetricCrypto ac = new AsymmetricCrypto(jTFAlgorithm.getText());
                        File input = new File("KeyPair/input_asymmetric_file_encryption.txt");
                        File output = new File("KeyPair/encrypted_asymmetric_file.txt");

                        if (!input.exists()) {
                            JOptionPane.showConfirmDialog(cf, "Fisierul de input nu exista !", "!", JOptionPane.ERROR_MESSAGE);
                        }

                        else if (input.exists()) {
                            if (output.exists()) {
                                output.delete(); output.createNewFile();

                                ac.encryptFile(ac.getFileInBytes(input), output);

                                encrypted = String.valueOf(ac.getFileInBytes(output));

                            }
                        }



                    } catch (Exception e2) {
                        // TODO Auto-generated catch block
                        e2.printStackTrace();
                    }

                    System.out.println("Criptarea a fost facuta cu succes !");
                    JOptionPane.showMessageDialog(cf, encrypted, "Rezultat criptare", JOptionPane.INFORMATION_MESSAGE);

                    createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare criptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
    }


    private ActionListener getPerformAsymmetricFileDecryption () {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if (JTFKeyLength.getText() != null && JTFKeyLength.getText() != " "
                        && JTFKeyLength.getText().length() != 0 && jTFAlgorithm.getText() != null
                        && jTFAlgorithm.getText() != " " && jTFAlgorithm.getText().length() != 0) {

                    try {
                        AsymmetricCrypto ac = new AsymmetricCrypto(jTFAlgorithm.getText());
                        File input = new File("KeyPair/encrypted_text_asymmmetric.txt");
                        File output = new File("KeyPair/decrypted_asymmetric_file.txt");

                        
                        if (!input.exists()) {
                            JOptionPane.showConfirmDialog(cf, "Fisierul de input nu exista !", "!", JOptionPane.ERROR_MESSAGE);
                        } else if (input.exists()) {
                            if (output.exists()) {
                                output.delete(); output.createNewFile();
                                String s = FileUtils.readFileToString(input);
                                
                                System.out.println(RSA.decrypt(s, RSA.privateKey));

                                
                                //ac.decryptFile(ac.getFileInBytes(input), output);
                                encrypted = RSA.decrypt(s, RSA.privateKey);

                                //encrypted = String.valueOf(ac.getFileInBytes(output));

                            }
                        }



                    } catch (Exception e2) {
                        // TODO Auto-generated catch block
                        e2.printStackTrace();
                    }

                    System.out.println("Deriptarea a fost facuta cu succes !");
                    JOptionPane.showMessageDialog(cf, encrypted, "Rezultat decriptare", JOptionPane.INFORMATION_MESSAGE);

                    createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare decriptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
    }

    private ActionListener getPerformSymmetricListener() {
        return new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if (JTFHelper.getText() != null && JTFHelper.getText() != " " && JTFHelper.getText().length() != 0
                        && jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0 && JTFSymmetricKeyAlg.getText() != null
                        && JTFSymmetricKeyAlg.getText() != " " && JTFSymmetricKeyAlg.getText().length() != 0) {

                    try {
                        SymmetricCrypto sc = new SymmetricCrypto(jTFAlgorithm.getText());
                        SymmetricKey sk = new SymmetricKey();
                        byte[] textToEncrypt = JTFHelper.getText().getBytes("ISO-8859-1");
                        encryptedBytes = SymmetricCrypto.encryptText(textToEncrypt, sc.getSecretKey(JTFSymmetricKeyAlg.getText()), sc.getSymmetricCryptoIV());
                        System.out.println(new Base64().encode(encryptedBytes));
                        encrypted = new String (new Base64().encode(encryptedBytes)); //new String(encryptedBytes, "ISO-8859-1");
                        System.out.println("Encrypted text after encryption: " + encrypted);
                        File file = new File("KeyPair/encrypted_text_symmmetric.txt");
                        FileWriter fw = new FileWriter(file);
                        BufferedWriter bw = new BufferedWriter(fw);
                        if (file.exists()) {
                            file.delete();
                            file.createNewFile();
                            bw.write(encrypted);
                            bw.close();

                            JOptionPane.showMessageDialog(cf, encrypted, "Rezultat criptare",
                                    JOptionPane.INFORMATION_MESSAGE);

                            // System.out.println("Decrypted text: " + new String(SymmetricCrypto.decryptedText(encryptedBytes, sc.getSecretKey(JTFSymmetricKeyAlg.getText()), sc.getSymmetricCryptoIV())));
                            createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                        }
                    } catch (Exception e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    }


                } else {
                    String message = "Nu ati completat unul dintre campurile necesare criptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
    }


    private ActionListener getPerformSymmetricDecryptionListener() {
        return new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if (jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0 && JTFSymmetricKeyAlg.getText() != null
                        && JTFSymmetricKeyAlg.getText() != " " && JTFSymmetricKeyAlg.getText().length() != 0) {

                    try {
                        SymmetricCrypto sc = new SymmetricCrypto(jTFAlgorithm.getText());
                        SymmetricKey sk = new SymmetricKey();
                      /*  int i =0; byte byteVal=0;
                        FileInputStream fis = new FileInputStream(new File ("KeyPair/encrypted_text_symmmetric.txt") );
                        while ((i =fis.read())>=0) {
                            byteVal = (byte)i;
                        }
                        
                        String convert = String.valueOf(byteVal);
                        byte[] textToDecrypt1 = convert.getBytes() ;*/
                        //byte[] textToDecrypt = sc.getFileInBytes(new File("KeyPair/encrypted_text_symmmetric.txt"));
                        InputStream in = new FileInputStream(new File("KeyPair/encrypted_text_symmmetric.txt"));
                        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                        StringBuilder out = new StringBuilder();
                        String line;
                        while ((line=reader.readLine()) !=null) {
                            out.append (line);
                        }
                        System.out.println(out.toString());
                        reader.close();
                        byte[] textToDecrypt = new Base64().decode(out.toString());
                       decrypted =new String(SymmetricCrypto.decryptedText(textToDecrypt, sc.getSecretKey(JTFSymmetricKeyAlg.getText()), sc.getSymmetricCryptoIV()));

                        //decrypted = new String(decryptedBytes, "ISO-8859-1");
                        System.out.println("Textul decriptat este: " + decrypted);
                        JOptionPane.showMessageDialog(cf, decrypted, "Rezultat decriptare",
                                JOptionPane.INFORMATION_MESSAGE);

                        createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException
                             ex) {
                        Logger.getLogger(CryptoFrame.class.getName()).log(Level.SEVERE, null, ex);

                    } catch (FileNotFoundException e1) {
                        e1.printStackTrace();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    } catch (BadPaddingException e1) {
                        e1.printStackTrace();
                    } catch (InvalidKeyException e1) {
                        e1.printStackTrace();
                    } catch (IllegalBlockSizeException e1) {
                        e1.printStackTrace();
                    } catch (InvalidAlgorithmParameterException e1) {
                        e1.printStackTrace();
                    }
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare decriptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
    }

    private ActionListener getPerformSymmetricFileEncryption() {
        return new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if (jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0 && JTFSymmetricKeyAlg.getText() != null
                        && JTFSymmetricKeyAlg.getText() != " " && JTFSymmetricKeyAlg.getText().length() != 0
                        && JTFFileKey.getText() != null && JTFFileKey.getText() != " " && JTFFileKey.getText().length() != 0) {

                    try {
                        SymmetricCrypto sc = new SymmetricCrypto(jTFAlgorithm.getText());
                        Random random = new Random();
                        int rand = random.nextInt(1000);
                        String text = "Testing encryption on files" + String.valueOf(rand);
                        File inputFile = new File("KeyPair/input_encryption_file.txt");
                        File encryptedFile = new File("KeyPair/encrypted_symmetric_file.txt");
                        //File decryptedFile = new File ("KeyPair/decrypted_file.txt");
                        if (inputFile.exists() && encryptedFile.exists()) {
                            inputFile.delete();
                            encryptedFile.delete();
                            inputFile.createNewFile();
                            encryptedFile.createNewFile();
                            FileWriter fw = new FileWriter(inputFile);
                            BufferedWriter bw = new BufferedWriter(fw);

                            bw.write(text);
                            bw.close();

                            SymmetricCrypto.encryptFile(sc.getKeySpecFile(JTFFileKey.getText(), JTFSymmetricKeyAlg.getText()), inputFile, encryptedFile, sc.getIV());
                            encrypted = new String(sc.getFileInBytes(encryptedFile), "UTF-8");


                        }
                    } catch (NoSuchPaddingException | NoSuchAlgorithmException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    } catch (IOException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    }
                    JOptionPane.showMessageDialog(cf, encrypted, "Rezultat criptare",
                            JOptionPane.INFORMATION_MESSAGE);

                    createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare criptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }


            }
        };
    }

    private ActionListener getPerformSymmetricFileDecryption() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0 && JTFSymmetricKeyAlg.getText() != null
                        && JTFSymmetricKeyAlg.getText() != " " && JTFSymmetricKeyAlg.getText().length() != 0
                        && JTFFileKey.getText() != null && JTFFileKey.getText() != " " && JTFFileKey.getText().length() != 0) {

                    try {
                        SymmetricCrypto sc = new SymmetricCrypto(jTFAlgorithm.getText());
                          /*  Random random = new Random();
                            int rand = random.nextInt(1000);
                            String text = "Testing encryption on files" + String.valueOf(rand);
                            File inputFile = new File ("KeyPair/input_encryption_file.txt");*/
                        File encryptedFile = new File("KeyPair/encrypted_symmetric_file.txt");
                        File decryptedFile = new File("KeyPair/decrypted_symmetric_file.txt");





                        if (!encryptedFile.exists()) {
                            JOptionPane.showConfirmDialog(cf, "Fisierul criptat nu exista !", "!", JOptionPane.ERROR_MESSAGE);
                        } else if (encryptedFile.exists() && decryptedFile.exists()) {
                            decryptedFile.delete();
                            try {
                                decryptedFile.createNewFile();
                            } catch (IOException e1) {
                                e1.printStackTrace();
                            }
                        }

                        SymmetricCrypto.decryptedFile(sc.getKeySpecFile(JTFFileKey.getText(), JTFSymmetricKeyAlg.getText()), encryptedFile, decryptedFile, sc.getIV());

                        decrypted = new String(sc.getFileInBytes(decryptedFile), "UTF-8");


                    } catch (NoSuchPaddingException e1) {
                        e1.printStackTrace();
                    } catch (NoSuchAlgorithmException e1) {
                        e1.printStackTrace();
                    } catch (UnsupportedEncodingException e1) {
                        e1.printStackTrace();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }

                    JOptionPane.showMessageDialog(cf, decrypted, "Rezultat decriptare",
                            JOptionPane.INFORMATION_MESSAGE);

                    createSendEmailButton("carolinaangelica26@gmail.com", decrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare decriptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);

                }

            }

        };
    }
            private ActionListener getPerformSymmetricImgEncryption () {
              return new ActionListener() {
                  @Override
                  public void actionPerformed(ActionEvent actionEvent) {
                      if (jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                              && jTFAlgorithm.getText().length() != 0 && JTFSymmetricKeyAlg.getText() != null
                              && JTFSymmetricKeyAlg.getText() != " " && JTFSymmetricKeyAlg.getText().length() != 0
                              ) {
                                String returnValue;
                          try {
                              SymmetricCrypto sc = new SymmetricCrypto(jTFAlgorithm.getText());
                              SymmetricKey sk = new SymmetricKey(JTFSymmetricKeyAlg.getText());
                              File inputFile = JFileChooser.getSelectedFile();
                              File encryptedFile = new File("KeyPair/transformed_symmetric_img.txt");
                              //File decryptedFile = new File ("KeyPair/decrypted_file.txt");

                              if (inputFile.exists() && encryptedFile.exists()) {
                                  encryptedFile.delete();
                                  encryptedFile.createNewFile();


                                  SymmetricCrypto.encryptImage(sc.getkeyImag(JTFSymmetricKeyAlg.getText()),inputFile, encryptedFile, sc.getIV());
                                  returnValue = String.valueOf(sc.getFileInBytes(encryptedFile));
                                  System.out.println("Success !");
                                  /*SymmetricCrypto.decryptImage(sc.getkeyImag("AES"), output1, input2, sc.getIV() );
                                  System.out.println("Decrypted !");*/

                                  try {
                                      encrypted = sc.encryptText(returnValue, JTFSymmetricKeyAlg.getText());
                                  } catch (BadPaddingException e) {
                                      e.printStackTrace();
                                  } catch (IllegalBlockSizeException e) {
                                      e.printStackTrace();
                                  } catch (InvalidAlgorithmParameterException e) {
                                      e.printStackTrace();
                                  } catch (InvalidKeyException e) {
                                      e.printStackTrace();
                                  }
                                  File encryptedImg = new File("KeyPair/encrypted_symmetric_img.txt");

                                    if (encryptedImg.exists()) {
                                        encryptedImg.delete();
                                        encryptedImg.createNewFile();
                                        FileWriter fw1 = new FileWriter(encryptedImg);
                                        BufferedWriter bw1 = new BufferedWriter(fw1);
                                        bw1.write(encrypted);
                                        bw1.close();

                                    }


                              }
                          } catch (NoSuchPaddingException | NoSuchAlgorithmException e1) {
                              // TODO Auto-generated catch block
                              e1.printStackTrace();
                          } catch (IOException e1) {
                              // TODO Auto-generated catch block
                              e1.printStackTrace();
                          }
                          JOptionPane.showMessageDialog(cf, encrypted, "Rezultat criptare",
                                  JOptionPane.INFORMATION_MESSAGE);

                          createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                      } else {
                          String message = "Nu ati completat unul dintre campurile necesare criptarii !";
                          JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                      }
                  }
              };
            }

            private ActionListener getPerformSymmetricImgDecryption () {

            return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if (jTFAlgorithm.getText() != null && jTFAlgorithm.getText() != " "
                        && jTFAlgorithm.getText().length() != 0 && JTFSymmetricKeyAlg.getText() != null
                        && JTFSymmetricKeyAlg.getText() != " " && JTFSymmetricKeyAlg.getText().length() != 0
                        ) {
                            String returnValue = null;
                    try {
                        SymmetricCrypto sc = new SymmetricCrypto(jTFAlgorithm.getText());

                        File encryptedFile = new File("KeyPair/encrypted_symmetric_img.txt");
                        File decryptedFile = new File ("KeyPair/decrypted_symmetric_img.txt");
                        File transformedImg = new File("KeyPair/img_out.jpg");

                        if (!encryptedFile.exists()) {
                            JOptionPane.showConfirmDialog(cf, "Fisierul criptat nu exista !", "!", JOptionPane.ERROR_MESSAGE);
                        }
                         else if (encryptedFile.exists()) {
                            decryptedFile.delete(); transformedImg.delete();
                            decryptedFile.createNewFile(); transformedImg.createNewFile();
                            FileWriter fw = new FileWriter(decryptedFile);
                            BufferedWriter bw = new BufferedWriter(fw);
                            returnValue = sc.decryptText(readFileAsString("KeyPair/encrypted_symmetric_img.txt"), JTFSymmetricKeyAlg.getText());

                                 System.out.println("return value is: " + returnValue);
                                 bw.write( returnValue);
                                 bw.close();
                                 System.out.println("Success !");

                        }

                        SymmetricCrypto.decryptImage(sc.getkeyImag(JTFSymmetricKeyAlg.getText()), decryptedFile, transformedImg, sc.getIV());


                    } catch (NoSuchPaddingException | NoSuchAlgorithmException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    } catch (IOException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    } catch (InvalidAlgorithmParameterException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    JLabel image = new JLabel(createImageIcon("KeyPair/img_out.jpg"));
                    JOptionPane.showMessageDialog (cf, image, "Rezultat decriptare", JOptionPane.INFORMATION_MESSAGE );

                    createSendEmailButton("carolinaangelica26@gmail.com", encrypted);
                } else {
                    String message = "Nu ati completat unul dintre campurile necesare decriptarii !";
                    JOptionPane.showMessageDialog(cf, message, "!", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
            }

    private void createSendEmailButton(String receiverAddress, String result) {
        removeAllActionListenersFromButton(sendEmail);
        sendEmail.setVisible(true);
        sendEmail.setText("Trimite Email");

        sendEmail.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMailWithTheResult(receiverAddress, result);
            }
        });
    }

    private void createSelectFileButton() {
        removeAllActionListenersFromButton(selectFile);
        selectFile.setVisible(true);
        selectFile.setText("Alege fisier");
        selectFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                setselectFileDetails();
            }
        });
    }

    private void changeStateCryptoElements(boolean state, boolean assymetric, boolean isSymmetric, boolean isEncryptText, boolean isFile) {
        jLabelHelper.setVisible(state && isEncryptText);
        jLabelAlg.setVisible(state);
        jLabelKeyLength.setVisible(state && assymetric);
        jLabelSymmetricKeyAlg.setVisible(state && isSymmetric);
        jLabelFileKey.setVisible(state && isFile);
        JTFHelper.setVisible(state && isEncryptText);
        jTFAlgorithm.setVisible(state);
        JTFKeyLength.setVisible(state && assymetric);
        JTFSymmetricKeyAlg.setVisible(state && isSymmetric);
        JTFFileKey.setVisible(state && isFile);
        JFileChooser.setVisible(state && isFile);

        performCrypto.setVisible(state);
        sendEmail.setVisible(false);
        selectFile.setVisible(false);
    }

    private void clearCryptoTextFields() {
        JTFHelper.setText(null);
        JTFKeyLength.setText(null);
        jTFAlgorithm.setText(null);
        JTFSymmetricKeyAlg.setText(null);

    }

    private boolean sendMailWithTheResult(String receiverAddress, String result) {
        EmailService ems = new EmailService();
        ems.setSubject("Test Subject..");
        ems.setBody("Test Body...");
        Properties props = System.getProperties();

        props.put("fromEmail", "utmblog2018@gmail.com");
        props.put("password", "Utmblog123");
        props.put("toEmail", receiverAddress);
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.SocketFactory.port", "465");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory"); // SSL Factory
        // Class
        props.put("mail.smtp.auth", "true"); // Enabling SMTP Authentication
        props.put("mail.smtp.port", "465"); // SMTP Port
        Authenticator auth = new Authenticator() {
            // override the getPasswordAuthentication method
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(System.getProperty("fromEmail"), System.getProperty("password"));
            }
        };

        Session session = Session.getInstance(props, auth);

        String fromEmail = System.getProperty("fromEmail");
        String toEmail = System.getProperty("toEmail");
        File file = new File("./encrypted.txt");
        BufferedWriter bw;

        if (file.exists()) {
            file.delete();
        }
        try {
            file.createNewFile();
            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(result);
            bw.close();
        } catch (IOException e1) {
            e1.printStackTrace();
            return false;
        }

        EmailService.sendAttachmentEmail(session, fromEmail, toEmail, ems.getSubject(), ems.getBody(), file);

        return true;
    }

    private ImageIcon createImageIcon(String path) {
        java.net.URL imgURL = getClass().getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL);
        } else {
            System.err.println("Couldn't find file: " + path);
            return null;
        }
    }

    private void setselectFileDetails() {

        JFileChooser.setCurrentDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
        JFileChooser.setName("Alege fisier");
        int value = JFileChooser.showOpenDialog(cf);
        if (value == JFileChooser.APPROVE_OPTION) {
            File selected = JFileChooser.getSelectedFile();
            System.out.println("Cale fisier selectat: " + selected.getAbsolutePath() + "\n" + "Nume fisier selectat: " + selected.getName());

        }
    }

    public String readFileAsString(String fileName)throws Exception
    {
        String data = "";
        data = new String(Files.readAllBytes(Paths.get(fileName)));
        return data;
    }

    private void removeAllActionListenersFromButton(JButton button) {
        for (ActionListener al : button.getActionListeners()) {
            button.removeActionListener(al);
        }
    }
}
