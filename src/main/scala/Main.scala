import scala.io.StdIn

object Main {

  def main(args: Array[String]): Unit = {
    while (true) {
      println("\nВыберите опцию:")
      println("1) Зашифровать")
      println("2) Расшифровать")
//      println("3) Зашифровать cbc")
//      println("4) Расшифровать cbc")
      println("5) Выход")
      val option = StdIn.readInt()
      option match {
        case 1 => run(isEncrypt = true)
        case 2 => run(isEncrypt = false)
        case 3 => run2(isEncrypt = true)
        case 4 => run2Decrypt()
        case 5 => return
      }
    }
  }

  //412
  //10010111

  def run2Decrypt(): Unit = {
    println("Введите текст:")
    val text = StdIn.readLine()
    val byteSeq = text.map(char => roundTo(char.toInt.toBinaryString, 8))
    println(" Символы в двоичной системе: " + byteSeq.mkString(" "))
    println("Введите ключ:")
    val key = StdIn.readInt()
    val binaryKey = getBinaryKey(key, 10)
    println(" Ключ в двоичном формате: " + binaryKey)
    val (subKey1, subKey2) = getSubKeys(binaryKey)
    println(" Первый подключ: " + subKey1)
    println(" Второй подключ: " + subKey2)
    println("Введите вектор инициализации: ")
    val initVector = StdIn.readLine()
    var isFirst = true
    var resList: List[String] = List()
    var encList: List[String] = List()
    byteSeq.foreach(symbol =>
      if (isFirst) {
        isFirst = false
        val decrypted = encryptSymbol(symbol, subKey1, subKey2, isEncrypt = false)
        println(" Расшифрованный символ: " + decrypted)
        encList = encList.appended(symbol)
        val afterXor = roundTo((BigInt(decrypted, 2) ^ BigInt(initVector, 2)).toString(2), 8)
        println(" XOR первого сивола с вектором инициализации: " + afterXor)
        resList = resList.appended(afterXor)
      } else {
        val decrypted = encryptSymbol(symbol, subKey1, subKey2, isEncrypt = false)
        println(" Расшифрованный символ: " + decrypted)
        val afterXor = roundTo((BigInt(decrypted, 2) ^ BigInt(encList.last, 2)).toString(2), 8)
        println(" XOR символа с предыдущим результатом: " + afterXor)
        encList = encList.appended(symbol)
        resList = resList.appended(afterXor)
      })
    val result = resList.map(elem => BigInt(elem, 2).toInt)
    println("Зашифрованный текст в двоичном формате:" + resList.mkString(""))
    println("Зашифрованный текст :" + result.map(_.toChar).mkString(""))
  }

  def run2(isEncrypt: Boolean): Unit = {
    println("Введите текст:")
    val text = StdIn.readLine()
    val byteSeq = text.map(char => roundTo(char.toInt.toBinaryString, 8))
    println(" Символы в двоичной системе: " + byteSeq.mkString(" "))
    println("Введите ключ:")
    val key = StdIn.readInt()
    val binaryKey = getBinaryKey(key, 10)
    println(" Ключ в двоичном формате: " + binaryKey)
    val (subKey1, subKey2) = getSubKeys(binaryKey)
    println(" Первый подключ: " + subKey1)
    println(" Второй подключ: " + subKey2)
    println("Введите вектор инициализации: ")
    val initVector = StdIn.readLine()
    var isFirst = true
    var resList: List[String] = List()
    byteSeq.foreach(symbol =>
      if (isFirst) {
        isFirst = false
        val afterXor = roundTo((BigInt(symbol, 2) ^ BigInt(initVector, 2)).toString(2), 8)
        println(" XOR первого символа с вектором инициализации: " + afterXor)
        val encrypted = encryptSymbol(afterXor, subKey1, subKey2, isEncrypt = true)
        println(" Зашифрованный символ: " + encrypted)
        resList = resList.appended(encrypted)
    } else {
        val afterXor1 = roundTo((BigInt(symbol, 2) ^ BigInt(resList.last, 2)).toString(2), 8)
        println(" XOR символа с предыдущим результатом: " + afterXor1)
        val encrypted = encryptSymbol(afterXor1, subKey1, subKey2, isEncrypt = true)
        println(" Зашифрованный символ: " + encrypted)
        resList = resList.appended(encrypted)
      })
    val result = resList.map(elem => BigInt(elem, 2).toInt)
    println("Зашифрованный текст в двоичном формате:" + resList.mkString(""))
    println("Зашифрованный текст :" + result.map(_.toChar).mkString(""))
  }

  def encryptSymbol(binarySymbol: String, subKey1: String, subKey2: String,  isEncrypt: Boolean): String = {
    val IP = List(2, 6, 3, 1, 4, 8, 5, 7)
    val (left, right) = {
      val symbolAfterIP = IP.map(index => binarySymbol(index -1)).mkString("")
      (symbolAfterIP.substring(0, 4), symbolAfterIP.substring(4))
    }
    val firstFunction = if(isEncrypt) functionK(left, right, subKey1) else functionK(left, right, subKey2)
    val afterSW = right + firstFunction
    val secondFunction = if (isEncrypt) functionK(right, firstFunction, subKey2) else functionK(right, firstFunction, subKey1)
    val reverseIP = List(4, 1, 3, 5, 7, 2, 8, 6)
    val result = reverseIP.map(index => (secondFunction + firstFunction)(index - 1)).mkString("")
    val resultSymbol = BigInt(result, 2).toInt
    result
  }

  def run(isEncrypt: Boolean): Unit = {
    println("Введите ключ:")
    val key = StdIn.readInt()
    val binaryKey = getBinaryKey(key, 10)
    println(" Ключ в двоичном формате: " + binaryKey)
    val (subKey1, subKey2) = getSubKeys(binaryKey)
    println(" Первый подключ: " + subKey1)
    println(" Второй подключ: " + subKey2)
    println("Введите символ:")
    val symbol = StdIn.readLine()
    var binarySymbol1 = 'a'
    if (symbol.toIntOption.isDefined) binarySymbol1 = symbol.toInt.toChar
    else binarySymbol1 = symbol.head
    val binarySymbol = getBinaryKey(binarySymbol1.toInt, 8)
    println(" Символ в двоичном формате: " + binarySymbol)
    val IP = List(2, 6, 3, 1, 4, 8, 5, 7)
    val (left, right) = {
      val symbolAfterIP = IP.map(index => binarySymbol(index -1)).mkString("")
      (symbolAfterIP.substring(0, 4), symbolAfterIP.substring(4))
    }
    println(" Результат IP: " + left + right)
    val firstFunction = if(isEncrypt) functionK(left, right, subKey1) else functionK(left, right, subKey2)
    println(" Результат первого отображения F: " + firstFunction)
    val afterSW = right + firstFunction
    println(" Результат SW перестановки: " + afterSW)
    val secondFunction = if (isEncrypt) functionK(right, firstFunction, subKey2) else functionK(right, firstFunction, subKey1)
    println(" Результат второго отображения F: " + secondFunction)
    println("zzxc " + secondFunction + firstFunction)
    val reverseIP = List(4, 1, 3, 5, 7, 2, 8, 6)
    val result = reverseIP.map(index => (secondFunction + firstFunction)(index - 1)).mkString("")
    println(" Результат IP-1: " + result)
    val resultSymbol = BigInt(result, 2).toInt
    println(" Зашифрованный символ в 10 формате: " + resultSymbol)
    println(" Зашифрованный символ: " + resultSymbol.toChar)
  }
  
  def getBinaryKey(key: Int, len: Int): String = {
    val commonBinaryKey = key.toBinaryString
    if (commonBinaryKey.length != len) {
      val zeroes = len - commonBinaryKey.length
      ("0" * zeroes).concat(commonBinaryKey)
    } else commonBinaryKey
  }

  def getSubKeys(key: String): (String, String) = {
    val P10 = List(3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
    val keyAfterP10 = P10.map(index => key(index - 1)).mkString("")
    val keyAfterFirstShift = leftShift(keyAfterP10, 1)
    val keyAfterSecondShift = leftShift(keyAfterFirstShift, 2)
    val P8 = List(6, 3, 7, 4, 8, 5, 10, 9)
    val firstSubKey = P8.map(index => keyAfterFirstShift(index - 1)).mkString("")
    val secondSubKey = P8.map(index => keyAfterSecondShift(index - 1)).mkString("")
    (firstSubKey, secondSubKey)
  }

  def leftShift(string: String, k: Int): String = {
    val firstPart = string.substring(0, 5)
    val secondPart = string.substring(5)
    firstPart.substring(k % 5) + firstPart.substring(0, k % 5) +
      secondPart.substring(k % 5) + secondPart.substring(0, k % 5)
  }

  def roundTo(string: String, int: Int): String = {
    ("0" * (int - string.length)) + string
  }

  def functionK(left: String, right: String, key: String): String = {
    val ep = List(4, 1, 2, 3, 2, 3, 4, 1)
    val afterEP = ep.map(index => right(index - 1)).mkString("")
    val (leftAfterXOR, rightAfterXOR) = {
      val xorInt = (BigInt(afterEP, 2) ^ BigInt(key, 2)).toString(2)
      val res = roundTo(xorInt, 8)
      (res.substring(0, 4), res.substring(4))
    }
    val slMatrix = List(
      List(1, 0, 3, 2),
      List(3, 2, 1, 0),
      List(0, 2, 1, 3),
      List(3, 1, 3, 1)
    )
    val srMatrix = List(
      List(1, 1, 2, 3),
      List(2, 0, 1, 3),
      List(3, 0, 1, 0),
      List(2, 1, 0, 3)
    )
    val LMatrixElem = {
      val row = BigInt(leftAfterXOR.head.toString + leftAfterXOR.last.toString, 2).toInt
      val column = BigInt(leftAfterXOR(1).toString + leftAfterXOR(2).toString, 2).toInt
      val elem = slMatrix(row)(column).toBinaryString
      if (elem.length == 1) "0" + elem else elem
    }
    val RMatrixElem = {
      val row = BigInt(rightAfterXOR.head.toString + rightAfterXOR.last.toString, 2).toInt
      val column = BigInt(rightAfterXOR(1).toString + rightAfterXOR(2).toString, 2).toInt
      val elem = srMatrix(row)(column).toBinaryString
      if (elem.length == 1) "0" + elem else elem
    }
    println("матрицы " + LMatrixElem + RMatrixElem)
    val P4 = List(2, 4, 3, 1)
    val afterP4 = P4.map(index => (LMatrixElem + RMatrixElem)(index - 1)).mkString("")
    println("p4 " + afterP4)
    val result = (BigInt(left, 2) ^ BigInt(afterP4, 2)).toString(2)
    roundTo(result, 4)
  }
}