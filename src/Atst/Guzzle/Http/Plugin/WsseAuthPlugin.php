<?php
namespace Atst\Guzzle\Http\Plugin;

use Guzzle\Common\Event;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Adds WSSE auth headers based on http://www.xml.com/pub/a/2003/12/17/dive.html
 *
 * @see    http://www.xml.com/pub/a/2003/12/17/dive.html
 * @author Dave Marshall <dave.marshall@atstsolutions.co.uk>
 */
class WsseAuthPlugin implements EventSubscriberInterface
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * @var Callable
     */
    private $digester;

    /**
     * @var Callable
     */
    private $noncer;

    /**
     * Constructor
     *
     * @param string   $username  The username
     * @param string   $password  The password
     * @param Callable $digester  Optional closure to create digest
     * @param Callable $noncer    Optional closure to create nonce
     */
    public function __construct($username, $password, $digester = null, $noncer = null)
    {
        $this->username = $username;
        $this->password = $password;

        $this->noncer = array($this, 'noncer');
        $this->digester = array($this, 'digester');

        if ($digester !== null) {
            if (!is_callable($digester)) {
                throw new \InvalidArgumentException("\$digester must be callable, " . gettype($digester) . " passed");
            }
            $this->digester = $digester;
        }

        if ($noncer !== null) {
            if (!is_callable($noncer)) {
                throw new \InvalidArgumentException("\$noncer must be callable, " . gettype($noncer) . " passed");
            }
            $this->noncer = $noncer;
        }
    }


    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents()
    {
        return array('client.create_request' => 'onRequestCreate');
    }

    /**
     * Add WSSE auth headers
     *
     * @param Event $event
     */
    public function onRequestCreate(Event $event)
    {
        $request = $event['request'];

        $nonce = call_user_func($this->noncer);
        $created = date('r');
        $digest = call_user_func($this->digester, $nonce, $created, $this->password);

        $request->addHeaders(array(
            "Authorization" => "WSSE profile=\"UsernameToken\"",
            "X-WSSE" => "UsernameToken Username=\"{$this->username}\", PasswordDigest=\"$digest\", Nonce=\"$nonce\", Created=\"$created\"",
        ));
    }

    /**
     * Digest
     *
     * @param string $nonce
     */
    public static function digester($nonce, $created, $password)
    {
        return base64_encode(sha1(base64_decode($nonce) . $created . $password, true));
    }

    /**
     * Noncer
     *
     * @return string
     */
    public static function noncer()
    {
        return hash('sha512', uniqid(true));
    }


}



